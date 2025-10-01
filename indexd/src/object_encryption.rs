use chacha20poly1305::aead::{Aead, OsRng};
use chacha20poly1305::{AeadCore, KeyInit, XChaCha20Poly1305};
use sia::blake2::Blake2b256;
use sia::encryption::EncryptionKey;
use sia::signing::PrivateKey;
use sia::types::Hash256;
use thiserror::Error;

const NONCE_SIZE: usize = 24;

#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("decryption error")]
    Decryption,
    #[error("invalid encryption key length")]
    KeyLength,
}

pub(crate) fn derive_encryption_key(key: &[u8], salt: &[u8], domain: &[u8]) -> EncryptionKey {
    let hkdf = hkdf::SimpleHkdf::<Blake2b256>::new(Some(salt), key);
    let mut okm = [0u8; 32];
    hkdf.expand(domain, &mut okm).unwrap();
    okm.into()
}

pub(crate) fn seal_master_key(
    app_key: &PrivateKey,
    object_id: &Hash256,
    encryption_key: &EncryptionKey,
) -> Vec<u8> {
    let master_encryption_key =
        derive_encryption_key(app_key.as_ref(), object_id.as_ref(), b"master");
    let encryption_key_cipher = XChaCha20Poly1305::new(master_encryption_key.as_ref().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let encrypted_master_key = encryption_key_cipher
        .encrypt(&nonce, encryption_key.as_ref().as_ref())
        .expect("encryption failed");
    [nonce.to_vec(), encrypted_master_key].concat()
}

pub(crate) fn open_encryption_key(
    app_key: &PrivateKey,
    object_id: &Hash256,
    encrypted_master_key: &[u8],
) -> Result<EncryptionKey, DecryptError> {
    if encrypted_master_key.len() < NONCE_SIZE {
        return Err(DecryptError::Decryption);
    }
    let master_encryption_key =
        derive_encryption_key(app_key.as_ref(), object_id.as_ref(), b"master");
    let encryption_key_cipher = XChaCha20Poly1305::new(master_encryption_key.as_ref().into());
    let (nonce_bytes, ciphertext) = encrypted_master_key.split_at(NONCE_SIZE);
    let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);
    let decrypted_master_key = encryption_key_cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| DecryptError::Decryption)?;
    EncryptionKey::try_from(decrypted_master_key.as_ref()).map_err(|_| DecryptError::KeyLength)
}

pub(crate) fn seal_metadata(
    master_key: &EncryptionKey,
    object_id: &Hash256,
    metadata: &[u8],
) -> Vec<u8> {
    let metadata_encryption_key =
        derive_encryption_key(master_key.as_ref(), object_id.as_ref(), b"metadata");
    let metadata_cipher = XChaCha20Poly1305::new(metadata_encryption_key.as_ref().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let encrypted_metadata = metadata_cipher
        .encrypt(&nonce, metadata)
        .expect("encryption failed");
    [nonce.to_vec(), encrypted_metadata].concat()
}

pub(crate) fn open_metadata(
    master_key: &EncryptionKey,
    object_id: &Hash256,
    encrypted_metadata: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    if encrypted_metadata.len() < NONCE_SIZE {
        return Err(DecryptError::Decryption);
    }
    let metadata_encryption_key =
        derive_encryption_key(master_key.as_ref(), object_id.as_ref(), b"metadata");
    let metadata_cipher = XChaCha20Poly1305::new(metadata_encryption_key.as_ref().into());
    let (nonce_bytes, ciphertext) = encrypted_metadata.split_at(NONCE_SIZE);
    let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);
    let decrypted_metadata = metadata_cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| DecryptError::Decryption)?;
    Ok(decrypted_metadata)
}
