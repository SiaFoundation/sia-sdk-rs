// chacha20poly1305 0.10.x re-exports generic-array 0.x which is deprecated.
// Remove this allow when upgrading to chacha20poly1305 0.11.0 stable.
#![allow(deprecated)]

use std::io;

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::aead::generic_array::GenericArray;

use crate::frame::{AEAD_NONCE_SIZE, AEAD_TAG_SIZE, PacketCipher};

pub(crate) struct SeqCipher {
    aead: chacha20poly1305::ChaCha20Poly1305,
    our_nonce: [u8; AEAD_NONCE_SIZE],
    their_nonce: [u8; AEAD_NONCE_SIZE],
}

/// Increments the first 8 bytes of a nonce as a little-endian u64.
fn inc_nonce(nonce: &mut [u8; AEAD_NONCE_SIZE]) {
    let counter = u64::from_le_bytes(nonce[..8].try_into().expect("nonce is 12 bytes"));
    nonce[..8].copy_from_slice(&(counter + 1).to_le_bytes());
}

impl PacketCipher for SeqCipher {
    fn encrypt_in_place(&mut self, buf: &mut [u8]) {
        let plaintext_len = buf.len() - AEAD_TAG_SIZE;
        let nonce = GenericArray::from_slice(&self.our_nonce);
        let tag = self
            .aead
            .encrypt_in_place_detached(nonce, &[], &mut buf[..plaintext_len])
            .expect("encryption cannot fail");
        buf[plaintext_len..].copy_from_slice(&tag);
        inc_nonce(&mut self.our_nonce);
    }

    fn decrypt_in_place(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let plaintext_len = buf.len() - AEAD_TAG_SIZE;
        let nonce = GenericArray::from_slice(&self.their_nonce);
        let (ct, tag_bytes) = buf.split_at_mut(plaintext_len);
        let tag = GenericArray::from_slice(tag_bytes);
        self.aead
            .decrypt_in_place_detached(nonce, &[], ct, tag)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD decryption failed"))?;
        inc_nonce(&mut self.their_nonce);
        Ok(plaintext_len)
    }
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

    use super::*;

    fn test_cipher_pair() -> (SeqCipher, SeqCipher) {
        let key = [0x42u8; 32];
        let aead1 = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
        let aead2 = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
        let mut c1 = SeqCipher {
            aead: aead1,
            our_nonce: [0u8; AEAD_NONCE_SIZE],
            their_nonce: [0u8; AEAD_NONCE_SIZE],
        };
        let mut c2 = SeqCipher {
            aead: aead2,
            our_nonce: [0u8; AEAD_NONCE_SIZE],
            their_nonce: [0u8; AEAD_NONCE_SIZE],
        };
        // flip nonces like the handshake does
        c2.our_nonce[AEAD_NONCE_SIZE - 1] ^= 0x80;
        c1.their_nonce[AEAD_NONCE_SIZE - 1] ^= 0x80;
        (c1, c2)
    }

    #[test]
    fn inc_nonce_increments() {
        let mut nonce = [0u8; AEAD_NONCE_SIZE];
        inc_nonce(&mut nonce);
        assert_eq!(u64::from_le_bytes(nonce[..8].try_into().unwrap()), 1);
        inc_nonce(&mut nonce);
        assert_eq!(u64::from_le_bytes(nonce[..8].try_into().unwrap()), 2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (mut c1, mut c2) = test_cipher_pair();
        let plaintext = b"hello world";
        let mut buf = vec![0u8; plaintext.len() + AEAD_TAG_SIZE];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        c1.encrypt_in_place(&mut buf);
        // ciphertext should differ from plaintext
        assert_ne!(&buf[..plaintext.len()], plaintext.as_slice());

        let pt_len = c2.decrypt_in_place(&mut buf).unwrap();
        assert_eq!(&buf[..pt_len], plaintext.as_slice());
    }

    #[test]
    fn sequential_nonces() {
        let (mut c1, mut c2) = test_cipher_pair();

        for i in 0u8..5 {
            let msg = [i; 16];
            let mut buf = vec![0u8; msg.len() + AEAD_TAG_SIZE];
            buf[..msg.len()].copy_from_slice(&msg);

            c1.encrypt_in_place(&mut buf);
            let pt_len = c2.decrypt_in_place(&mut buf).unwrap();
            assert_eq!(&buf[..pt_len], &msg);
        }
    }

    #[test]
    fn decrypt_wrong_nonce_fails() {
        let (mut c1, _c2) = test_cipher_pair();
        let plaintext = b"secret";
        let mut buf = vec![0u8; plaintext.len() + AEAD_TAG_SIZE];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        c1.encrypt_in_place(&mut buf);

        // decrypting with c1 (wrong nonce direction) should fail
        let result = c1.decrypt_in_place(&mut buf);
        assert!(result.is_err());
    }
}
