use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use serde::{Deserialize, Serialize};
use sia_core::encoding::{SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};
use zeroize::ZeroizeOnDrop;

/// A 256-bit symmetric encryption key used to encrypt and decrypt slab data.
#[derive(SiaEncode, SiaDecode, Clone, Debug, ZeroizeOnDrop, PartialEq)]
pub struct EncryptionKey([u8; 32]);

impl From<[u8; 32]> for EncryptionKey {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8]> for EncryptionKey {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() != 32 {
            return Err("invalid key length");
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(value);
        Ok(Self(key))
    }
}

impl AsRef<[u8; 32]> for EncryptionKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serialize for EncryptionKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = BASE64_STANDARD.encode(self.0);
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for EncryptionKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        EncryptionKey::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

/// Encrypts a single shard using XChaCha20. To decrypt the shard, call this
/// function again with the same key.
/// NOTE: don't reuse the same key for the same shard as it will compromise the
/// security of the encryption. Always use a freshly generated key.
pub(crate) fn encrypt_shard(key: &EncryptionKey, index: u8, offset: usize, shard: &mut [u8]) {
    let mut nonce: [u8; 24] = [0u8; 24]; // XChaCha20 nonce size
    nonce[0] = index;
    let mut cipher = XChaCha20::new(key.as_ref().into(), &nonce.into());
    cipher.seek(offset);
    cipher.apply_keystream(shard);
}

/// Encrypts or decrypts the recovered shards.
pub(crate) fn encrypt_recovered_shards(
    key: &EncryptionKey,
    shard_start: u8,
    offset: usize,
    shards: &mut [Option<impl AsMut<[u8]>>],
) {
    shards.iter_mut().enumerate().for_each(|(i, shard)| {
        if let Some(shard) = shard {
            encrypt_shard(key, shard_start + i as u8, offset, shard.as_mut());
        }
    });
}

pub(crate) struct Chacha20Cipher {
    inner: XChaCha20,
    key: EncryptionKey,
    offset: u64,
    nonce: [u8; 24],
}

impl Chacha20Cipher {
    const MAX_BYTES_PER_NONCE: u64 = u32::MAX as u64 * 64;

    fn rekey_cipher(key: &EncryptionKey, offset: u64, mut nonce: [u8; 24]) -> XChaCha20 {
        nonce[16..24].copy_from_slice(&(offset / Self::MAX_BYTES_PER_NONCE).to_le_bytes());
        XChaCha20::new_from_slices(key.as_ref(), &nonce).unwrap()
    }

    /// Apply keystream to `buf` in place rekeying as necessary
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        let remaining_keystream =
            Self::MAX_BYTES_PER_NONCE - (self.offset % Self::MAX_BYTES_PER_NONCE);
        if buf.len() as u64 <= remaining_keystream {
            self.offset += buf.len() as u64;
            self.inner.apply_keystream(buf);
            return;
        }

        let (first, second) = buf.split_at_mut(remaining_keystream as usize);
        self.offset += remaining_keystream;
        self.inner.apply_keystream(first);

        // unreachable in practice with V1 rekeying per slab, but left for compatibility
        // with V0
        self.inner = Self::rekey_cipher(&self.key, self.offset, self.nonce);
        self.offset += second.len() as u64;
        self.inner.apply_keystream(second);
    }

    /// Initalizes the cipher with an empty nonce.
    ///
    /// Keys should never be re-used.
    pub fn new_v0(key: EncryptionKey, offset: u64) -> Self {
        let mut cipher = Self::rekey_cipher(&key, offset, [0u8; 24]);
        cipher.seek(offset % Self::MAX_BYTES_PER_NONCE);
        Self {
            inner: cipher,
            key,
            offset,
            nonce: [0u8; 24],
        }
    }

    /// Initializes the cipher using the slab key as a nonce.
    ///
    /// Key re-use is safe, but not recommended.
    pub fn new_v1(data_key: EncryptionKey, offset: u64, slab_key: &EncryptionKey) -> Self {
        let nonce: [u8; 24] = slab_key.as_ref()[..24].try_into().unwrap();
        // this purposefully does not call rekey so we do not clobber the nonce
        let mut cipher = XChaCha20::new(data_key.as_ref().into(), &nonce.into());
        cipher.seek(offset % Self::MAX_BYTES_PER_NONCE);
        Self {
            inner: cipher,
            key: data_key,
            offset,
            nonce,
        }
    }
}

#[cfg(test)]
mod test {
    use sia_core::rhp4::SECTOR_SIZE;

    use super::*;

    fn random_bytes(buf: &mut [u8]) {
        getrandom::fill(buf).unwrap();
    }

    fn random_key() -> EncryptionKey {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();
        EncryptionKey::from(key)
    }

    fn encrypt_shards(key: &EncryptionKey, shard_start: u8, offset: usize, shards: &mut [Vec<u8>]) {
        shards.iter_mut().enumerate().for_each(|(i, shard)| {
            encrypt_shard(key, shard_start + i as u8, offset, shard);
        });
    }

    #[sia_core_derive::cross_target_test]
    fn test_encrypt_sector_roundtrip() {
        let key = EncryptionKey::from([1u8; 32]);

        let mut sector = vec![0u8; SECTOR_SIZE];
        random_bytes(&mut sector);

        let original = sector.clone();
        encrypt_shard(&key, 0, 0, &mut sector);
        assert_ne!(sector, original);
        encrypt_shard(&key, 0, 0, &mut sector);
        assert_eq!(sector, original);
    }

    #[sia_core_derive::cross_target_test]
    fn test_encrypt_shards() {
        let key = EncryptionKey::from([1u8; 32]);
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

    // Direct port of Go SDK's sdk/encrypt_test.go:TestEncryptRoundtrip
    #[sia_core_derive::cross_target_test]
    fn test_encrypt_roundtrip() {
        const MAX_BYTES_PER_NONCE: u64 = u32::MAX as u64 * 64;

        let mut data = [0u8; 4096];
        random_bytes(&mut data);

        let key = random_key();

        for offset in [
            0,
            16,
            31,
            63,
            64,
            96,
            128,
            2048,
            4096,
            MAX_BYTES_PER_NONCE - 127,
            MAX_BYTES_PER_NONCE - 128,
            MAX_BYTES_PER_NONCE - 63,
            MAX_BYTES_PER_NONCE - 64,
            MAX_BYTES_PER_NONCE,
            2 * MAX_BYTES_PER_NONCE,
        ] {
            let mut ciphertext = data.to_vec();
            Chacha20Cipher::new_v0(key.clone(), offset).apply_keystream(&mut ciphertext);

            let mut plaintext = ciphertext.clone();
            Chacha20Cipher::new_v0(key.clone(), offset).apply_keystream(&mut plaintext);

            assert_eq!(plaintext, data, "roundtrip failed at offset {offset}");
        }
    }

    #[sia_core_derive::cross_target_test]
    fn test_v1_encrypt_roundtrip() {
        const MAX_BYTES_PER_NONCE: u64 = u32::MAX as u64 * 64;

        let mut data = [0u8; 4096];
        random_bytes(&mut data);

        let data_key = random_key();

        for offset in [
            0,
            16,
            31,
            63,
            64,
            96,
            128,
            2048,
            4096,
            MAX_BYTES_PER_NONCE - 127,
            MAX_BYTES_PER_NONCE - 128,
            MAX_BYTES_PER_NONCE - 63,
            MAX_BYTES_PER_NONCE - 64,
            MAX_BYTES_PER_NONCE,
            2 * MAX_BYTES_PER_NONCE,
        ] {
            let mut ciphertext = data.to_vec();
            let slab_key = random_key();
            Chacha20Cipher::new_v1(data_key.clone(), offset, &slab_key)
                .apply_keystream(&mut ciphertext);

            let mut plaintext = ciphertext.clone();
            Chacha20Cipher::new_v1(data_key.clone(), offset, &slab_key)
                .apply_keystream(&mut plaintext);

            assert_eq!(plaintext, data, "roundtrip failed at offset {offset}");
        }
    }
}
