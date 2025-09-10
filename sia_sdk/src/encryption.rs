use chacha20::cipher::{
    KeyIvInit, StreamCipher, StreamCipherCoreWrapper, StreamCipherError, StreamCipherSeek,
};
use chacha20::{XChaCha20, XChaChaCore};
use pin_project_lite::pin_project;
use rayon::prelude::*;
use sha2::digest::consts::{B0, B1};
use sha2::digest::typenum::{UInt, UTerm};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("StreamCipherError: {0}")]
    StreamCipherError(StreamCipherError),
}

impl From<StreamCipherError> for Error {
    fn from(err: StreamCipherError) -> Self {
        Error::StreamCipherError(err)
    }
}

type Result<T> = std::result::Result<T, Error>;

/// encrypts the provided shards using XChaCha20. To decrypt the shards, call
/// this function again with the same key.
/// NOTE: don't reuse the same key for the same set of shards as it will
/// compromise the security of the encryption. Always use a freshly generated
/// key.
pub fn encrypt_shards(key: &[u8; 32], shard_start: u8, offset: usize, shards: &mut Vec<Vec<u8>>) {
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
pub fn encrypt_shard(key: &[u8; 32], index: u8, offset: usize, shard: &mut [u8]) {
    let mut nonce: [u8; 24] = [0u8; 24]; // XChaCha20 nonce size
    nonce[0] = index;
    let mut cipher = XChaCha20::new(key.into(), &nonce.into());
    cipher.seek(offset);
    cipher.apply_keystream(shard);
}

pin_project! {
    pub struct CipherReader<R: AsyncRead> {
        #[pin]
        inner: R,
        cipher: StreamCipherCoreWrapper<XChaChaCore<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B1>, B0>>>,
    }
}

impl<R: AsyncRead> CipherReader<R> {
    pub fn new(inner: R, key: &[u8; 32], offset: usize) -> Result<Self> {
        let nonce: [u8; 24] = [0u8; 24];
        let mut cipher = XChaCha20::new(key.into(), &nonce.into());
        cipher.try_seek(offset)?;
        Ok(Self { inner, cipher })
    }
}

impl<R: AsyncRead> AsyncRead for CipherReader<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.project();
        let initial_filled = buf.filled().len();
        let poll = this.inner.poll_read(cx, buf);

        // apply the cipher to the newly read bytes
        this.cipher
            .apply_keystream(&mut buf.filled_mut()[initial_filled..]);
        poll
    }
}

pin_project! {
    pub struct CipherWriter<W: AsyncWrite> {
        #[pin]
        inner: W,
        cipher: StreamCipherCoreWrapper<XChaChaCore<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B1>, B0>>>,
        buf: Vec<u8>
    }
}

impl<'w, W: AsyncWrite> CipherWriter<W> {
    pub fn new(inner: W, key: &[u8; 32], offset: usize) -> Result<Self> {
        let nonce: [u8; 24] = [0u8; 24];
        let mut cipher = XChaCha20::new(key.into(), &nonce.into());
        cipher.try_seek(offset)?;
        Ok(Self {
            inner,
            cipher,
            buf: Vec::new(),
        })
    }
}

impl<'w, W: AsyncWrite> AsyncWrite for CipherWriter<W> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.project();
        this.buf.resize(buf.len(), 0);
        this.buf.copy_from_slice(buf);
        this.cipher.apply_keystream(this.buf);
        this.inner.poll_write(cx, &this.buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.project();
        this.inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.project();
        this.inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod test {
    use rand::RngCore;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::rhp::SECTOR_SIZE;

    use super::*;

    #[test]
    fn test_encrypt_sector_roundtrip() {
        let key = [1u8; 32];

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
        let key = [1u8; 32];
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
        let key = [1u8; 32];
        let data = b"lorem ipsum dolor sit amet, consectetur adipiscing elit";

        for offset in [0, 10, 20, 30] {
            let mut reader = CipherReader::new(data.as_ref(), &key, offset).unwrap();
            let mut cipher_text = vec![0u8; data.len()];
            reader.read_exact(&mut cipher_text).await.unwrap();
            assert_ne!(cipher_text, data);

            let mut writer = CipherWriter::new(Vec::new(), &key, offset).unwrap();
            writer.write_all(&cipher_text).await.unwrap();
            let plaintext = writer.inner;
            assert_eq!(plaintext, data);
        }
    }
}
