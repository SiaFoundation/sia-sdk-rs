use crate::encryption::EncryptionKey;
use chacha20poly1305::aead::{Aead, Generate};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use sia_core::blake2::Blake2b256;
use sia_core::signing::PrivateKey;
use sia_core::types::Hash256;
use thiserror::Error;

const NONCE_SIZE: usize = 24;

#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("decryption error")]
    Decryption,
    #[error("invalid encryption key length")]
    KeyLength,
}

pub(crate) fn derive(key: &[u8], salt: &[u8], domain: &[u8], okm: &mut [u8]) {
    let hkdf = hkdf::SimpleHkdf::<Blake2b256>::new(Some(salt), key);
    hkdf.expand(domain, okm).unwrap();
}

pub(crate) fn derive_encryption_key(key: &[u8], salt: &[u8], domain: &[u8]) -> EncryptionKey {
    let hkdf = hkdf::SimpleHkdf::<Blake2b256>::new(Some(salt), key);
    let mut okm = [0u8; 32];
    hkdf.expand(domain, &mut okm).unwrap();
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
