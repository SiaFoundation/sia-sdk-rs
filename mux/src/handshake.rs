use std::io;

use crate::frame::{PacketCipher, AEAD_NONCE_SIZE, AEAD_TAG_SIZE};

pub(crate) struct SeqCipher {
    aead: chacha20poly1305::ChaCha20Poly1305,
    our_nonce: [u8; AEAD_NONCE_SIZE],
    their_nonce: [u8; AEAD_NONCE_SIZE],
}
