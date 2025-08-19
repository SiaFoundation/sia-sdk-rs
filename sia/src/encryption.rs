use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    XChaCha20,
};

pub(crate) fn encrypt_shards(key: &[u8; 32], shards: &mut [Vec<u8>]) {
    let mut nonce = [0u8; 24]; // XChaCha20 nonce size
    for (i, shard) in shards.iter_mut().enumerate() {
        nonce[0] = i as u8;
        let mut cipher = XChaCha20::new(key.into(), &nonce.into());
        cipher.apply_keystream(shard);
    }
}
