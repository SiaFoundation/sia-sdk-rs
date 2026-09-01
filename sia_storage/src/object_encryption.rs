use crate::encryption::EncryptionKey;
use blake2b_simd::Params;
use chacha20poly1305::aead::{Aead, Generate};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use sia_core::signing::PrivateKey;
use sia_core::types::Hash256;
use thiserror::Error;

const NONCE_SIZE: usize = 24;

/// BLAKE2b's block size, which HMAC pads its key out to.
const HMAC_BLOCK_SIZE: usize = 128;

/// The output size of BLAKE2b-256, one HKDF block.
const HASH_SIZE: usize = 32;

#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("decryption error")]
    Decryption,
    #[error("invalid encryption key length")]
    KeyLength,
}

/// HMAC-BLAKE2b-256 (RFC 2104) over the concatenation of `parts`.
fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; HASH_SIZE] {
    let mut params = Params::new();
    params.hash_length(HASH_SIZE);

    // Keys longer than a block are replaced by their hash, shorter ones are
    // zero-padded.
    let mut block = [0u8; HMAC_BLOCK_SIZE];
    if key.len() > HMAC_BLOCK_SIZE {
        block[..HASH_SIZE].copy_from_slice(params.hash(key).as_bytes());
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; HMAC_BLOCK_SIZE];
    let mut opad = [0x5cu8; HMAC_BLOCK_SIZE];
    for i in 0..HMAC_BLOCK_SIZE {
        ipad[i] ^= block[i];
        opad[i] ^= block[i];
    }

    let mut inner = params.to_state();
    inner.update(&ipad);
    for part in parts {
        inner.update(part);
    }
    let inner = inner.finalize();

    params
        .to_state()
        .update(&opad)
        .update(inner.as_bytes())
        .finalize()
        .as_bytes()
        .try_into()
        .expect("blake2b output is 32 bytes")
}

/// Fills `okm` with HKDF (RFC 5869) key material derived from `key`, using
/// HMAC-BLAKE2b-256 as the underlying PRF.
pub(crate) fn hkdf(key: &[u8], salt: &[u8], domain: &[u8], okm: &mut [u8]) {
    assert!(okm.len() <= 255 * HASH_SIZE, "okm is too long");

    let prk = hmac(salt, &[key]);
    let mut prev = [0u8; HASH_SIZE];
    for (i, chunk) in okm.chunks_mut(HASH_SIZE).enumerate() {
        let counter = [i as u8 + 1];
        prev = if i == 0 {
            hmac(&prk, &[domain, &counter])
        } else {
            hmac(&prk, &[&prev, domain, &counter])
        };
        chunk.copy_from_slice(&prev[..chunk.len()]);
    }
}

pub(crate) fn derive_encryption_key(key: &[u8], salt: &[u8], domain: &[u8]) -> EncryptionKey {
    let mut okm = [0u8; 32];
    hkdf(key, salt, domain, &mut okm);
    okm.into()
}

pub(crate) fn seal_data_key(
    app_key: &PrivateKey,
    object_id: &Hash256,
    encryption_key: &EncryptionKey,
) -> Vec<u8> {
    let data_encryption_key =
        derive_encryption_key(app_key.as_ref(), object_id.as_ref(), b"dataKey");
    let encryption_key_cipher = XChaCha20Poly1305::new(data_encryption_key.as_ref().into());
    let nonce = XNonce::generate();
    let encrypted_data_key = encryption_key_cipher
        .encrypt(&nonce, encryption_key.as_ref().as_ref())
        .expect("encryption failed");
    [nonce.to_vec(), encrypted_data_key].concat()
}

pub(crate) fn seal_metadata_key(
    app_key: &PrivateKey,
    object_id: &Hash256,
    encryption_key: &EncryptionKey,
) -> Vec<u8> {
    let meta_encryption_key =
        derive_encryption_key(app_key.as_ref(), object_id.as_ref(), b"metadataKey");
    let encryption_key_cipher = XChaCha20Poly1305::new(meta_encryption_key.as_ref().into());
    let nonce = XNonce::generate();
    let encrypted_meta_key = encryption_key_cipher
        .encrypt(&nonce, encryption_key.as_ref().as_ref())
        .expect("encryption failed");
    [nonce.to_vec(), encrypted_meta_key].concat()
}

pub(crate) fn open_data_key(
    app_key: &PrivateKey,
    object_id: &Hash256,
    encrypted_data_key: &[u8],
) -> Result<EncryptionKey, DecryptError> {
    if encrypted_data_key.len() < NONCE_SIZE {
        return Err(DecryptError::Decryption);
    }
    let data_encryption_key =
        derive_encryption_key(app_key.as_ref(), object_id.as_ref(), b"dataKey");
    let encryption_key_cipher = XChaCha20Poly1305::new(data_encryption_key.as_ref().into());
    let (nonce_bytes, ciphertext) = encrypted_data_key.split_at(NONCE_SIZE);
    let nonce_bytes: [u8; 24] = nonce_bytes.try_into().unwrap(); // safe due to length check above
    let nonce = XNonce::from(nonce_bytes);
    let decrypted_data_key = encryption_key_cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| DecryptError::Decryption)?;
    EncryptionKey::try_from(decrypted_data_key.as_ref()).map_err(|_| DecryptError::KeyLength)
}

pub(crate) fn open_metadata_key(
    app_key: &PrivateKey,
    object_id: &Hash256,
    encrypted_meta_key: &[u8],
) -> Result<EncryptionKey, DecryptError> {
    if encrypted_meta_key.len() < NONCE_SIZE {
        return Err(DecryptError::Decryption);
    }
    let meta_encryption_key =
        derive_encryption_key(app_key.as_ref(), object_id.as_ref(), b"metadataKey");
    let encryption_key_cipher = XChaCha20Poly1305::new(meta_encryption_key.as_ref().into());
    let (nonce_bytes, ciphertext) = encrypted_meta_key.split_at(NONCE_SIZE);
    let nonce_bytes: [u8; 24] = nonce_bytes.try_into().unwrap(); // safe due to length check above
    let nonce = XNonce::from(nonce_bytes);
    let decrypted_meta_key = encryption_key_cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| DecryptError::Decryption)?;
    EncryptionKey::try_from(decrypted_meta_key.as_ref()).map_err(|_| DecryptError::KeyLength)
}

pub(crate) fn seal_metadata(meta_key: &EncryptionKey, metadata: &[u8]) -> Vec<u8> {
    let metadata_cipher = XChaCha20Poly1305::new(meta_key.as_ref().into());
    let nonce = XNonce::generate();
    let encrypted_metadata = metadata_cipher
        .encrypt(&nonce, metadata)
        .expect("encryption failed");
    [nonce.to_vec(), encrypted_metadata].concat()
}

pub(crate) fn open_metadata(
    meta_key: &EncryptionKey,
    encrypted_metadata: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    if encrypted_metadata.len() < NONCE_SIZE {
        return Err(DecryptError::Decryption);
    }
    let metadata_cipher = XChaCha20Poly1305::new(meta_key.as_ref().into());
    let (nonce_bytes, ciphertext) = encrypted_metadata.split_at(NONCE_SIZE);
    let nonce_bytes: [u8; 24] = nonce_bytes.try_into().unwrap(); // safe due to length check above
    let nonce = XNonce::from(nonce_bytes);
    let decrypted_metadata = metadata_cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| DecryptError::Decryption)?;
    Ok(decrypted_metadata)
}

#[cfg(test)]
mod test {
    use super::*;

    /// Key material derived before the switch from the `hkdf` crate, to pin the
    /// derivation against existing objects. The third vector spans multiple
    /// HKDF blocks and uses a key longer than HMAC's block size.
    #[sia_core_derive::cross_target_test]
    fn test_derive_reference_vectors() {
        for (key, salt, domain, expected) in [
            (
                &b"key"[..],
                &b"salt"[..],
                &b"domain"[..],
                "ade655b1217719bb9c8c06da2e09069580b9972812bb2307a8f956cc0295db38",
            ),
            (
                &[][..],
                &[][..],
                &[][..],
                "7607ae73694d0c021897e87d4c6b4d0fdb54cb62736d4bbe76f57b52a063a03a",
            ),
            (
                &[0x0bu8; 80][..],
                &[0xaa; 200][..],
                &b"dataKey"[..],
                "0d17ac5d9dfc9de211f2ad97a72c3f2f70fb0b3e4101812e2d5c8092ab9ce4f5f1164e3ec17baded861db62b7b278b0797a7187cb7148e127abbf68ad03d08d673b5ef69148ee6d70c196deb36acb8d4843d108d4bf5dde96f71bac97e44708259bf9662",
            ),
        ] {
            let mut okm = vec![0u8; expected.len() / 2];
            hkdf(key, salt, domain, &mut okm);
            assert_eq!(hex::encode(&okm), expected);
        }
    }

    #[sia_core_derive::cross_target_test]
    fn test_data_key_seal_open_roundtrip() {
        let app_key = PrivateKey::from_seed(&[1u8; 32]);
        let object_id = Hash256::new([2u8; 32]);
        let data_key = EncryptionKey::from([3u8; 32]);

        let sealed = seal_data_key(&app_key, &object_id, &data_key);
        let opened = open_data_key(&app_key, &object_id, &sealed).expect("should open");
        assert_eq!(opened, data_key);
    }

    #[sia_core_derive::cross_target_test]
    fn test_open_data_key_rejects_wrong_key() {
        let app_key = PrivateKey::from_seed(&[1u8; 32]);
        let wrong_key = PrivateKey::from_seed(&[9u8; 32]);
        let object_id = Hash256::new([2u8; 32]);
        let data_key = EncryptionKey::from([3u8; 32]);

        // A different app key derives a different cipher, so the AEAD tag fails.
        let sealed = seal_data_key(&app_key, &object_id, &data_key);
        let err = open_data_key(&wrong_key, &object_id, &sealed)
            .expect_err("a wrong key must not decrypt");
        assert!(matches!(err, DecryptError::Decryption));
    }

    #[sia_core_derive::cross_target_test]
    fn test_open_data_key_rejects_truncated_ciphertext() {
        let app_key = PrivateKey::from_seed(&[1u8; 32]);
        let object_id = Hash256::new([2u8; 32]);

        // Shorter than the 24-byte nonce: rejected before any decryption.
        let err = open_data_key(&app_key, &object_id, &[0u8; NONCE_SIZE - 1])
            .expect_err("a truncated ciphertext must be rejected");
        assert!(matches!(err, DecryptError::Decryption));
    }
}
