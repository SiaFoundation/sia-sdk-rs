use crate::encoding::{SiaDecodable, SiaEncodable};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chacha20::XChaCha20;
use chacha20::cipher::inout::InOutBuf;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherError, StreamCipherSeek};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sia_derive::{SiaDecode, SiaEncode};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::ZeroizeOnDrop;

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

/// encrypts the provided shards using XChaCha20. To decrypt the shards, call
/// this function again with the same key.
/// NOTE: don't reuse the same key for the same set of shards as it will
/// compromise the security of the encryption. Always use a freshly generated
/// key.
pub fn encrypt_shards(
    key: &EncryptionKey,
    shard_start: u8,
    offset: usize,
    shards: &mut Vec<Vec<u8>>,
) {
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
pub fn encrypt_shard(key: &EncryptionKey, index: u8, offset: usize, shard: &mut [u8]) {
    let mut nonce: [u8; 24] = [0u8; 24]; // XChaCha20 nonce size
    nonce[0] = index;
    let mut cipher = XChaCha20::new(key.as_ref().into(), &nonce.into());
    cipher.seek(offset);
    cipher.apply_keystream(shard);
}

pub struct CipherReader<R: AsyncRead> {
    inner: R,
    cipher: Chacha20Cipher,
}

impl<R: AsyncRead> CipherReader<R> {
    pub fn new(inner: R, key: EncryptionKey, offset: usize) -> Self {
        Self {
            inner,
            cipher: Chacha20Cipher::new(key, offset as u64),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CipherReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let initial_filled = buf.filled().len();
        let poll = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);

        // apply the cipher to the newly read bytes
        self.cipher
            .apply_keystream(&mut buf.filled_mut()[initial_filled..]);
        poll
    }
}

pub struct CipherWriter<W: AsyncWrite> {
    inner: W,
    cipher: Chacha20Cipher,
    buf: Vec<u8>,
}

impl<W: AsyncWrite> CipherWriter<W> {
    pub fn new(inner: W, key: EncryptionKey, offset: usize) -> Self {
        Self {
            inner,
            cipher: Chacha20Cipher::new(key, offset as u64),
            buf: Vec::new(),
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CipherWriter<W> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.buf.resize(buf.len(), 0);
        this.buf.copy_from_slice(buf);
        this.cipher.apply_keystream(&mut this.buf);
        std::pin::Pin::new(&mut this.inner).poll_write(cx, &this.buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct Chacha20Cipher {
    inner: XChaCha20,
    key: EncryptionKey,
    nonce: [u8; 24],
    offset: u64,
}

impl Chacha20Cipher {
    const MAX_BYTES_PER_NONCE: u64 = u32::MAX as u64 * 64;

    fn nonce_for_offset(offset: u64) -> [u8; 24] {
        let mut nonce: [u8; 24] = [0u8; 24];
        nonce[16..24].copy_from_slice(&(offset / Self::MAX_BYTES_PER_NONCE).to_le_bytes());
        nonce
    }

    pub fn new(key: EncryptionKey, offset: u64) -> Self {
        let nonce = Self::nonce_for_offset(offset);
        let mut cipher = XChaCha20::new(key.as_ref().into(), &nonce.into());
        cipher.seek(offset % Self::MAX_BYTES_PER_NONCE);
        Self {
            inner: cipher,
            key,
            nonce,
            offset,
        }
    }
}

impl StreamCipher for Chacha20Cipher {
    fn check_remaining(&self, _data_len: usize) -> Result<(), StreamCipherError> {
        // we handle nonce rotation, so we can always process more data.
        Ok(())
    }

    fn unchecked_apply_keystream_inout(&mut self, buf: InOutBuf<'_, '_, u8>) {
        let remaining_keystream =
            Self::MAX_BYTES_PER_NONCE - (self.offset % Self::MAX_BYTES_PER_NONCE);

        if buf.len() as u64 <= remaining_keystream {
            self.offset += buf.len() as u64;
            self.inner.apply_keystream_inout(buf);
            return;
        }

        // we can't process the entire buffer with the current nonce, so we need
        // to split it
        let (first, second) = buf.split_at(remaining_keystream as usize);

        // the first part can be processed with the current nonce
        self.offset += first.len() as u64;
        self.inner.apply_keystream_inout(first);

        // update nonce and reinitialize cipher
        self.nonce = Self::nonce_for_offset(self.offset);
        self.inner = XChaCha20::new(self.key.as_ref().into(), &self.nonce.into());

        // encrypt the second part
        self.offset += second.len() as u64;
        self.inner.apply_keystream_inout(second);
    }

    fn unchecked_write_keystream(&mut self, buf: &mut [u8]) {
        buf.fill(0);
        self.unchecked_apply_keystream(buf);
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::rhp::SECTOR_SIZE;

    use super::*;

    #[test]
    fn test_encrypt_sector_roundtrip() {
        let key = EncryptionKey::from([1u8; 32]);

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

    #[tokio::test]
    async fn test_cipher_reader_writer() {
        let key = EncryptionKey::from([1u8; 32]);
        let data = b"lorem ipsum dolor sit amet, consectetur adipiscing elit";

        for offset in [0, 10, u32::MAX as usize * 64 - 10, u32::MAX as usize * 64] {
            let mut reader = CipherReader::new(data.as_ref(), key.clone(), offset);
            let mut cipher_text = vec![0u8; data.len()];
            reader.read_exact(&mut cipher_text).await.unwrap();
            assert_ne!(cipher_text, data);

            let mut writer = CipherWriter::new(Vec::new(), key.clone(), offset);
            writer.write_all(&cipher_text).await.unwrap();
            let plaintext = writer.inner;
            assert_eq!(plaintext, data);
        }
    }
}
