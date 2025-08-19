use std::u8;

use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

/// encrypts the provided shards using XChaCha20. To decrypt the shards, call
/// this function again with the same key.
/// NOTE: don't reuse the same key for the same set of shads as it will
/// compromise the security of the encryption. Always use a freshly generated
/// key.
#[allow(dead_code)]
pub(crate) fn encrypt_shards(key: &[u8; 32], shards: &mut [Vec<u8>], offset: usize) {
    assert!(shards.len() <= u8::MAX as usize);
    let mut nonce = [0u8; 24]; // XChaCha20 nonce size
    for (i, shard) in shards.iter_mut().enumerate() {
        nonce[0] = i as u8;
        let mut cipher = XChaCha20::new(key.into(), &nonce.into());
        cipher.seek(offset);
        cipher.apply_keystream(shard);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encrypt_shards() {
        let key = [1u8; 32];
        let mut shards = vec![vec![1, 2, 3], vec![4, 5, 6]];

        // encrypt
        encrypt_shards(&key, &mut shards, 0);
        assert_eq!(shards[0], vec![136, 154, 188]);
        assert_eq!(shards[1], vec![70, 216, 180]);

        // decrypt
        encrypt_shards(&key, &mut shards, 0);
        assert_eq!(shards[0], vec![1, 2, 3]);
        assert_eq!(shards[1], vec![4, 5, 6]);

        // encrypt with offset
        encrypt_shards(&key, &mut shards, 100);
        assert_eq!(shards[0], vec![6, 194, 192]);
        assert_eq!(shards[1], vec![236, 188, 165]);

        // decrypt with offset
        encrypt_shards(&key, &mut shards, 100);
        assert_eq!(shards[0], vec![1, 2, 3]);
        assert_eq!(shards[1], vec![4, 5, 6]);
    }
}
