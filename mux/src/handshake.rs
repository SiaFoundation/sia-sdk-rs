// chacha20poly1305 0.10.x re-exports generic-array 0.x which is deprecated.
// Remove this allow when upgrading to chacha20poly1305 0.11.0 stable.
#![allow(deprecated)]

use std::io;

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use ed25519_dalek::{SIGNATURE_LENGTH, Signer, SigningKey, Verifier, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey};

const X25519_PUBLIC_KEY_SIZE: usize = 32;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use std::time::Duration;

use thiserror::Error;

use crate::frame::{AEAD_NONCE_SIZE, AEAD_TAG_SIZE, FRAME_HEADER_SIZE, PacketCipher};

#[derive(Clone)]
pub(crate) struct SeqCipher {
    aead: chacha20poly1305::ChaCha20Poly1305,
    pub(crate) our_nonce: [u8; AEAD_NONCE_SIZE],
    pub(crate) their_nonce: [u8; AEAD_NONCE_SIZE],
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

const IPV6_MTU: u32 = 1440; // 1500-byte Ethernet frame - 40-byte IPv6 header - 20-byte TCP header

pub(crate) const CONN_SETTINGS_SIZE: usize = 4 + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnSettings {
    pub packet_size: u32,
    pub max_timeout: Duration,
}

impl ConnSettings {
    pub fn max_frame_size(&self) -> usize {
        self.packet_size as usize - AEAD_TAG_SIZE
    }

    pub fn max_payload_size(&self) -> usize {
        self.max_frame_size() - FRAME_HEADER_SIZE
    }
}

impl Default for ConnSettings {
    fn default() -> Self {
        Self {
            packet_size: IPV6_MTU * 3,
            max_timeout: Duration::from_secs(20 * 60),
        }
    }
}

impl From<ConnSettings> for [u8; CONN_SETTINGS_SIZE] {
    fn from(cs: ConnSettings) -> Self {
        let mut buf = [0u8; CONN_SETTINGS_SIZE];
        buf[0..4].copy_from_slice(&cs.packet_size.to_le_bytes());
        buf[4..8].copy_from_slice(&(cs.max_timeout.as_millis() as u32).to_le_bytes());
        buf
    }
}

impl TryFrom<&[u8]> for ConnSettings {
    type Error = ConnSettingsError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < CONN_SETTINGS_SIZE {
            return Err(ConnSettingsError::BufferTooShort);
        }
        Ok(Self {
            packet_size: u32::from_le_bytes(
                buf[0..4].try_into().expect("slice length checked above"),
            ),
            max_timeout: Duration::from_millis(u32::from_le_bytes(
                buf[4..8].try_into().expect("slice length checked above"),
            ) as u64),
        })
    }
}

#[derive(Debug, Error)]
pub enum ConnSettingsError {
    #[error("buffer too short for connection settings")]
    BufferTooShort,
    #[error("requested packet size ({0}) is too small")]
    PacketSizeTooSmall(u32),
    #[error("requested packet size ({0}) is too large")]
    PacketSizeTooLarge(u32),
    #[error("maximum timeout ({0:?}) is too short")]
    TimeoutTooShort(Duration),
    #[error("maximum timeout ({0:?}) is too long")]
    TimeoutTooLong(Duration),
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("could not write handshake request: {0}")]
    WriteRequest(io::Error),
    #[error("could not read handshake response: {0}")]
    ReadResponse(io::Error),
    #[error("invalid signature: {0}")]
    InvalidSignature(ed25519_dalek::SignatureError),
    #[error("could not decrypt settings: {0}")]
    DecryptSettings(io::Error),
    #[error("invalid settings payload: {0}")]
    InvalidSettings(ConnSettingsError),
    #[error("peer sent unacceptable settings: {0}")]
    UnacceptableSettings(ConnSettingsError),
    #[error("could not write settings: {0}")]
    WriteSettings(io::Error),
    #[error("could not read handshake request: {0}")]
    ReadRequest(io::Error),
    #[error("could not write handshake response: {0}")]
    WriteResponse(io::Error),
    #[error("could not read settings response: {0}")]
    ReadSettings(io::Error),
}

pub(crate) async fn initiate_handshake<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut T,
    their_key: &VerifyingKey,
    our_settings: ConnSettings,
) -> Result<(SeqCipher, ConnSettings), HandshakeError> {
    let our_secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let our_xpk = PublicKey::from(&our_secret);

    // write our X25519 public key
    conn.write_all(our_xpk.as_bytes())
        .await
        .map_err(HandshakeError::WriteRequest)?;

    // read their X25519 public key + Ed25519 signature + encrypted settings
    const SIG_START: usize = X25519_PUBLIC_KEY_SIZE;
    const SETTINGS_START: usize = X25519_PUBLIC_KEY_SIZE + SIGNATURE_LENGTH;
    let mut buf = vec![0u8; SETTINGS_START + CONN_SETTINGS_SIZE + AEAD_TAG_SIZE];
    conn.read_exact(&mut buf)
        .await
        .map_err(HandshakeError::ReadResponse)?;

    // verify signature over (our_xpk || their_xpk)
    let their_xpk = PublicKey::from(
        <[u8; X25519_PUBLIC_KEY_SIZE]>::try_from(&buf[..X25519_PUBLIC_KEY_SIZE])
            .expect("slice is 32 bytes"),
    );
    let mut msg = [0u8; X25519_PUBLIC_KEY_SIZE * 2];
    msg[..X25519_PUBLIC_KEY_SIZE].copy_from_slice(our_xpk.as_bytes());
    msg[X25519_PUBLIC_KEY_SIZE..].copy_from_slice(&buf[..X25519_PUBLIC_KEY_SIZE]);
    let sig = ed25519_dalek::Signature::from_slice(&buf[SIG_START..SETTINGS_START])
        .map_err(HandshakeError::InvalidSignature)?;
    their_key
        .verify(&msg, &sig)
        .map_err(HandshakeError::InvalidSignature)?;

    // derive shared secret via X25519
    let shared_secret = our_secret.diffie_hellman(&their_xpk);

    // derive symmetric key = BLAKE2b-256(secret || our_xpk || their_xpk)
    let key = blake2b_simd::Params::new()
        .hash_length(32)
        .to_state()
        .update(shared_secret.as_bytes())
        .update(our_xpk.as_bytes())
        .update(their_xpk.as_bytes())
        .finalize();
    let aead = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_bytes()));
    let mut cipher = SeqCipher {
        aead,
        our_nonce: [0u8; AEAD_NONCE_SIZE],
        their_nonce: [0u8; AEAD_NONCE_SIZE],
    };
    // initiator flips their_nonce high bit
    cipher.their_nonce[AEAD_NONCE_SIZE - 1] ^= 0x80;

    // decrypt their settings
    let plaintext_len = cipher
        .decrypt_in_place(&mut buf[SETTINGS_START..])
        .map_err(HandshakeError::DecryptSettings)?;
    let their_settings =
        ConnSettings::try_from(&buf[SETTINGS_START..SETTINGS_START + plaintext_len])
            .map_err(HandshakeError::InvalidSettings)?;
    let merged = merge_settings(our_settings, their_settings)
        .map_err(HandshakeError::UnacceptableSettings)?;

    // encrypt and write our settings
    let settings_bytes: [u8; CONN_SETTINGS_SIZE] = our_settings.into();
    let mut settings_buf = vec![0u8; CONN_SETTINGS_SIZE + AEAD_TAG_SIZE];
    settings_buf[..CONN_SETTINGS_SIZE].copy_from_slice(&settings_bytes);
    cipher.encrypt_in_place(&mut settings_buf);
    conn.write_all(&settings_buf)
        .await
        .map_err(HandshakeError::WriteSettings)?;

    Ok((cipher, merged))
}

pub(crate) async fn accept_handshake<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut T,
    our_key: &SigningKey,
    our_settings: ConnSettings,
) -> Result<(SeqCipher, ConnSettings), HandshakeError> {
    let our_secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let our_xpk = PublicKey::from(&our_secret);

    // read initiator's X25519 public key
    let mut their_xpk_bytes = [0u8; X25519_PUBLIC_KEY_SIZE];
    conn.read_exact(&mut their_xpk_bytes)
        .await
        .map_err(HandshakeError::ReadRequest)?;
    let their_xpk = PublicKey::from(their_xpk_bytes);

    // derive shared secret via X25519
    let shared_secret = our_secret.diffie_hellman(&their_xpk);

    // derive symmetric key = BLAKE2b-256(secret || initiator_xpk || responder_xpk)
    let key = blake2b_simd::Params::new()
        .hash_length(32)
        .to_state()
        .update(shared_secret.as_bytes())
        .update(&their_xpk_bytes)
        .update(our_xpk.as_bytes())
        .finalize();
    let aead = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_bytes()));
    let mut cipher = SeqCipher {
        aead,
        our_nonce: [0u8; AEAD_NONCE_SIZE],
        their_nonce: [0u8; AEAD_NONCE_SIZE],
    };
    // responder flips our_nonce high bit
    cipher.our_nonce[AEAD_NONCE_SIZE - 1] ^= 0x80;

    // sign (initiator_xpk || responder_xpk)
    let mut msg = [0u8; X25519_PUBLIC_KEY_SIZE * 2];
    msg[..X25519_PUBLIC_KEY_SIZE].copy_from_slice(&their_xpk_bytes);
    msg[X25519_PUBLIC_KEY_SIZE..].copy_from_slice(our_xpk.as_bytes());
    let sig = our_key.sign(&msg);

    // write response: our_xpk + signature + encrypted settings
    const SIG_START: usize = X25519_PUBLIC_KEY_SIZE;
    const SETTINGS_START: usize = X25519_PUBLIC_KEY_SIZE + SIGNATURE_LENGTH;
    let mut buf = vec![0u8; SETTINGS_START + CONN_SETTINGS_SIZE + AEAD_TAG_SIZE];
    buf[..X25519_PUBLIC_KEY_SIZE].copy_from_slice(our_xpk.as_bytes());
    buf[SIG_START..SETTINGS_START].copy_from_slice(&sig.to_bytes());
    let settings_bytes: [u8; CONN_SETTINGS_SIZE] = our_settings.into();
    buf[SETTINGS_START..SETTINGS_START + CONN_SETTINGS_SIZE].copy_from_slice(&settings_bytes);
    cipher.encrypt_in_place(&mut buf[SETTINGS_START..]);
    conn.write_all(&buf)
        .await
        .map_err(HandshakeError::WriteResponse)?;

    // read and decrypt initiator's settings
    let mut settings_buf = vec![0u8; CONN_SETTINGS_SIZE + AEAD_TAG_SIZE];
    conn.read_exact(&mut settings_buf)
        .await
        .map_err(HandshakeError::ReadSettings)?;
    let plaintext_len = cipher
        .decrypt_in_place(&mut settings_buf)
        .map_err(HandshakeError::DecryptSettings)?;
    let their_settings = ConnSettings::try_from(&settings_buf[..plaintext_len])
        .map_err(HandshakeError::InvalidSettings)?;
    let merged = merge_settings(our_settings, their_settings)
        .map_err(HandshakeError::UnacceptableSettings)?;

    Ok((cipher, merged))
}

pub(crate) fn merge_settings(
    ours: ConnSettings,
    theirs: ConnSettings,
) -> Result<ConnSettings, ConnSettingsError> {
    let merged = ConnSettings {
        packet_size: ours.packet_size.min(theirs.packet_size),
        max_timeout: ours.max_timeout.min(theirs.max_timeout),
    };
    match merged {
        s if s.packet_size < 1220 => Err(ConnSettingsError::PacketSizeTooSmall(s.packet_size)),
        s if s.packet_size > 32768 => Err(ConnSettingsError::PacketSizeTooLarge(s.packet_size)),
        s if s.max_timeout < Duration::from_secs(2 * 60) => {
            Err(ConnSettingsError::TimeoutTooShort(s.max_timeout))
        }
        s if s.max_timeout > Duration::from_secs(2 * 60 * 60) => {
            Err(ConnSettingsError::TimeoutTooLong(s.max_timeout))
        }
        _ => Ok(merged),
    }
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    use ed25519_dalek::Signer;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use x25519_dalek::StaticSecret;

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

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

    #[test]
    fn conn_settings_roundtrip() {
        let cs = ConnSettings {
            packet_size: 4320,
            max_timeout: Duration::from_secs(600),
        };
        let buf: [u8; CONN_SETTINGS_SIZE] = cs.into();
        let decoded = ConnSettings::try_from(buf.as_slice()).unwrap();
        assert_eq!(decoded, cs);
    }

    #[test]
    fn conn_settings_decode_too_short() {
        let buf = [0u8; 4];
        let result = ConnSettings::try_from(buf.as_slice());
        assert!(matches!(result, Err(ConnSettingsError::BufferTooShort)));
    }

    #[test]
    fn conn_settings_default_is_valid() {
        let result = merge_settings(ConnSettings::default(), ConnSettings::default());
        assert_eq!(result.unwrap(), ConnSettings::default());
    }

    #[test]
    fn merge_settings_picks_smaller() {
        let a = ConnSettings {
            packet_size: 4320,
            max_timeout: Duration::from_secs(20 * 60),
        };
        let b = ConnSettings {
            packet_size: 2000,
            max_timeout: Duration::from_secs(5 * 60),
        };
        let merged = merge_settings(a, b).unwrap();
        assert_eq!(merged.packet_size, 2000);
        assert_eq!(merged.max_timeout, Duration::from_secs(5 * 60));
    }

    #[test]
    fn merge_settings_rejects_too_small_packet() {
        let small = ConnSettings {
            packet_size: 500,
            max_timeout: Duration::from_secs(5 * 60),
        };
        let result = merge_settings(ConnSettings::default(), small);
        assert!(matches!(
            result,
            Err(ConnSettingsError::PacketSizeTooSmall(500))
        ));
    }

    #[test]
    fn merge_settings_rejects_too_short_timeout() {
        let short = ConnSettings {
            packet_size: 4320,
            max_timeout: Duration::from_secs(30),
        };
        let result = merge_settings(ConnSettings::default(), short);
        assert!(matches!(result, Err(ConnSettingsError::TimeoutTooShort(_))));
    }

    /// Simulates the responder (acceptor) side of the handshake for testing
    /// `initiate_handshake`. Returns the settings the initiator sent.
    async fn mock_handshake_responder(
        conn: &mut tokio::io::DuplexStream,
        signing_key: &ed25519_dalek::SigningKey,
        responder_settings: ConnSettings,
    ) -> ConnSettings {
        // read initiator's X25519 public key
        let mut initiator_xpk_bytes = [0u8; X25519_PUBLIC_KEY_SIZE];
        conn.read_exact(&mut initiator_xpk_bytes).await.unwrap();
        let initiator_xpk = PublicKey::from(initiator_xpk_bytes);

        // generate responder X25519 keypair and derive shared secret
        let responder_secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let responder_xpk = PublicKey::from(&responder_secret);
        let shared_secret = responder_secret.diffie_hellman(&initiator_xpk);

        // key = BLAKE2b-256(secret || initiator_xpk || responder_xpk)
        let key = blake2b_simd::Params::new()
            .hash_length(32)
            .to_state()
            .update(shared_secret.as_bytes())
            .update(&initiator_xpk_bytes)
            .update(responder_xpk.as_bytes())
            .finalize();
        let aead = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_bytes()));
        let mut cipher = SeqCipher {
            aead,
            our_nonce: [0u8; AEAD_NONCE_SIZE],
            their_nonce: [0u8; AEAD_NONCE_SIZE],
        };
        // responder flips our_nonce high bit
        cipher.our_nonce[AEAD_NONCE_SIZE - 1] ^= 0x80;

        // sign (initiator_xpk || responder_xpk)
        let mut msg = [0u8; X25519_PUBLIC_KEY_SIZE * 2];
        msg[..X25519_PUBLIC_KEY_SIZE].copy_from_slice(&initiator_xpk_bytes);
        msg[X25519_PUBLIC_KEY_SIZE..].copy_from_slice(responder_xpk.as_bytes());
        let sig = signing_key.sign(&msg);

        // build response: responder_xpk + signature + encrypted settings
        const SIG_START: usize = X25519_PUBLIC_KEY_SIZE;
        const SETTINGS_START: usize = X25519_PUBLIC_KEY_SIZE + SIGNATURE_LENGTH;
        let mut response = vec![0u8; SETTINGS_START + CONN_SETTINGS_SIZE + AEAD_TAG_SIZE];
        response[..X25519_PUBLIC_KEY_SIZE].copy_from_slice(responder_xpk.as_bytes());
        response[SIG_START..SETTINGS_START].copy_from_slice(&sig.to_bytes());
        let settings_bytes: [u8; CONN_SETTINGS_SIZE] = responder_settings.into();
        response[SETTINGS_START..SETTINGS_START + CONN_SETTINGS_SIZE]
            .copy_from_slice(&settings_bytes);
        cipher.encrypt_in_place(&mut response[SETTINGS_START..]);
        conn.write_all(&response).await.unwrap();

        // read and decrypt initiator's encrypted settings
        let mut settings_buf = vec![0u8; CONN_SETTINGS_SIZE + AEAD_TAG_SIZE];
        conn.read_exact(&mut settings_buf).await.unwrap();
        let plaintext_len = cipher.decrypt_in_place(&mut settings_buf).unwrap();
        ConnSettings::try_from(&settings_buf[..plaintext_len]).unwrap()
    }

    #[tokio::test]
    async fn initiate_handshake_success() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let (mut client, mut server) = tokio::io::duplex(1024);

        let responder = tokio::spawn(async move {
            mock_handshake_responder(&mut server, &signing_key, ConnSettings::default()).await
        });

        let (_, merged) = initiate_handshake(&mut client, &verifying_key, ConnSettings::default())
            .await
            .unwrap();

        let initiator_settings = responder.await.unwrap();
        assert_eq!(merged, ConnSettings::default());
        assert_eq!(initiator_settings, ConnSettings::default());
    }

    #[tokio::test]
    async fn initiate_handshake_merges_settings() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let (mut client, mut server) = tokio::io::duplex(1024);

        let smaller_settings = ConnSettings {
            packet_size: 2000,
            max_timeout: Duration::from_secs(5 * 60),
        };
        let responder = tokio::spawn(async move {
            mock_handshake_responder(&mut server, &signing_key, smaller_settings).await
        });

        let (_, merged) = initiate_handshake(&mut client, &verifying_key, ConnSettings::default())
            .await
            .unwrap();

        let _ = responder.await.unwrap();
        assert_eq!(merged.packet_size, 2000);
        assert_eq!(merged.max_timeout, Duration::from_secs(5 * 60));
    }

    #[tokio::test]
    async fn initiate_handshake_invalid_signature() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        // use a *different* verifying key so signature verification fails
        let wrong_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let wrong_verifying_key = wrong_key.verifying_key();
        let (mut client, mut server) = tokio::io::duplex(1024);

        tokio::spawn(async move {
            // We don't care if the responder panics after the initiator rejects
            let _ =
                mock_handshake_responder(&mut server, &signing_key, ConnSettings::default()).await;
        });

        let result =
            initiate_handshake(&mut client, &wrong_verifying_key, ConnSettings::default()).await;
        assert!(matches!(result, Err(HandshakeError::InvalidSignature(_))));
    }

    #[tokio::test]
    async fn initiate_handshake_rejects_bad_settings() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let (mut client, mut server) = tokio::io::duplex(1024);

        let bad_settings = ConnSettings {
            packet_size: 500, // below minimum of 1220
            max_timeout: Duration::from_secs(5 * 60),
        };
        tokio::spawn(async move {
            let _ = mock_handshake_responder(&mut server, &signing_key, bad_settings).await;
        });

        let result = initiate_handshake(&mut client, &verifying_key, ConnSettings::default()).await;
        assert!(matches!(
            result,
            Err(HandshakeError::UnacceptableSettings(_))
        ));
    }

    /// Cross-language test vectors generated from the Go implementation.
    /// Uses fixed X25519 and Ed25519 keys to verify byte-level compatibility
    /// of key derivation, AEAD encryption, and Ed25519 signatures.
    #[test]
    fn handshake_interop_vectors() {
        // Fixed keys (same as Go test)
        let initiator_xsk = StaticSecret::from([0x01u8; 32]);
        let responder_xsk = StaticSecret::from([0x02u8; 32]);
        let responder_ed_key = ed25519_dalek::SigningKey::from_bytes(&[0x03u8; 32]);

        // X25519 public keys
        let initiator_xpk = PublicKey::from(&initiator_xsk);
        let responder_xpk = PublicKey::from(&responder_xsk);
        assert_eq!(
            initiator_xpk.as_bytes(),
            hex("a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209").as_slice(),
        );
        assert_eq!(
            responder_xpk.as_bytes(),
            hex("ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59").as_slice(),
        );

        // Ed25519 public key
        assert_eq!(
            responder_ed_key.verifying_key().as_bytes(),
            hex("ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1").as_slice(),
        );

        // Shared secret (same from either perspective)
        let shared_secret_r = responder_xsk.diffie_hellman(&initiator_xpk);
        let shared_secret_i = initiator_xsk.diffie_hellman(&responder_xpk);
        assert_eq!(shared_secret_r.as_bytes(), shared_secret_i.as_bytes());
        assert_eq!(
            shared_secret_r.as_bytes(),
            hex("2ed76ab549b1e73c031eb49c9448f0798aea81b698279a0c3dc3e49fbfc4b953").as_slice(),
        );

        // Derived key = BLAKE2b-256(secret || initiator_xpk || responder_xpk)
        let key = blake2b_simd::Params::new()
            .hash_length(32)
            .to_state()
            .update(shared_secret_r.as_bytes())
            .update(initiator_xpk.as_bytes())
            .update(responder_xpk.as_bytes())
            .finalize();
        assert_eq!(
            key.as_bytes(),
            hex("aed23a79205772234ac29a04bdaf79b4384eec870dc9b4453e09f08e3338851a").as_slice(),
        );

        // Encoded default settings (packet_size=4320, max_timeout=1200000ms)
        let settings = ConnSettings::default();
        let settings_bytes: [u8; CONN_SETTINGS_SIZE] = settings.into();
        assert_eq!(&settings_bytes, hex("e0100000804f1200").as_slice());

        // --- Responder side ---
        let aead = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_bytes()));
        let mut rc = SeqCipher {
            aead,
            our_nonce: [0u8; AEAD_NONCE_SIZE],
            their_nonce: [0u8; AEAD_NONCE_SIZE],
        };
        rc.our_nonce[AEAD_NONCE_SIZE - 1] ^= 0x80;

        // Encrypt settings
        let mut responder_enc = vec![0u8; CONN_SETTINGS_SIZE + AEAD_TAG_SIZE];
        responder_enc[..CONN_SETTINGS_SIZE].copy_from_slice(&settings_bytes);
        rc.encrypt_in_place(&mut responder_enc);
        assert_eq!(
            responder_enc,
            hex("860bc7ecde1dd64fbe31793ffe5108ede85fedb42ed4b101"),
        );

        // Sign (initiator_xpk || responder_xpk)
        let mut msg = [0u8; X25519_PUBLIC_KEY_SIZE * 2];
        msg[..X25519_PUBLIC_KEY_SIZE].copy_from_slice(initiator_xpk.as_bytes());
        msg[X25519_PUBLIC_KEY_SIZE..].copy_from_slice(responder_xpk.as_bytes());
        let sig = responder_ed_key.sign(&msg);
        assert_eq!(
            &sig.to_bytes(),
            hex(
                "dc14a99c32a8631f0ea8834091f0478d5d632bdaa32eb73cc67f106585b32a32\
                 a8a0992508fbd74c08eb20f5fb8622c8e700c31cf2da5cfb07ecb4392033b90d"
            )
            .as_slice(),
        );

        // Full responder wire: xpk + sig + encrypted_settings
        let mut responder_wire = Vec::with_capacity(
            X25519_PUBLIC_KEY_SIZE + SIGNATURE_LENGTH + CONN_SETTINGS_SIZE + AEAD_TAG_SIZE,
        );
        responder_wire.extend_from_slice(responder_xpk.as_bytes());
        responder_wire.extend_from_slice(&sig.to_bytes());
        responder_wire.extend_from_slice(&responder_enc);
        assert_eq!(
            responder_wire,
            hex(
                "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59\
                 dc14a99c32a8631f0ea8834091f0478d5d632bdaa32eb73cc67f106585b32a32\
                 a8a0992508fbd74c08eb20f5fb8622c8e700c31cf2da5cfb07ecb4392033b90d\
                 860bc7ecde1dd64fbe31793ffe5108ede85fedb42ed4b101"
            ),
        );

        // --- Initiator side ---
        let iaead = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_bytes()));
        let mut ic = SeqCipher {
            aead: iaead,
            our_nonce: [0u8; AEAD_NONCE_SIZE],
            their_nonce: [0u8; AEAD_NONCE_SIZE],
        };
        ic.their_nonce[AEAD_NONCE_SIZE - 1] ^= 0x80;

        // Decrypt responder's settings
        let mut dec_buf = responder_enc.clone();
        let pt_len = ic.decrypt_in_place(&mut dec_buf).unwrap();
        assert_eq!(&dec_buf[..pt_len], &settings_bytes);

        // Encrypt initiator's settings
        let mut initiator_enc = vec![0u8; CONN_SETTINGS_SIZE + AEAD_TAG_SIZE];
        initiator_enc[..CONN_SETTINGS_SIZE].copy_from_slice(&settings_bytes);
        ic.encrypt_in_place(&mut initiator_enc);
        assert_eq!(
            initiator_enc,
            hex("f7ebc7f275b662fc7d59951bd5205703cf38ad13239efc27"),
        );

        // Responder decrypts initiator's settings
        let mut dec_buf2 = initiator_enc.clone();
        let pt_len2 = rc.decrypt_in_place(&mut dec_buf2).unwrap();
        assert_eq!(&dec_buf2[..pt_len2], &settings_bytes);
    }
}
