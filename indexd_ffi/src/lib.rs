uniffi::setup_scaffolding!();

use std::sync::{Arc, Mutex};
use std::task::Waker;

use indexd::{ConnectedState, PinnedSlab, SDK};
use log::debug;
use sia::rhp::SECTOR_SIZE;
use sia::signing::PrivateKey;
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

mod logging;
pub use logging::*;

#[derive(Debug, Error, uniffi::Error)]
pub enum Error {
    #[error("general error: {0}")]
    Msg(String),
}

#[derive(Debug, Error, uniffi::Error)]
pub enum BufferError {
    #[error("buffer closed")]
    Closed,
}

struct ChunkedBufferInner {
    buffer: Vec<u8>,
    closed: bool,
    waker: Option<Waker>,
}

#[derive(uniffi::Object, Clone)]
pub struct ChunkedBuffer {
    inner: Arc<Mutex<ChunkedBufferInner>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl ChunkedBuffer {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ChunkedBufferInner {
                buffer: Vec::with_capacity(SECTOR_SIZE),
                closed: false,
                waker: None,
            })),
        }
    }

    pub fn close(&self) -> Result<(), Error> {
        let mut inner = self.inner.lock().map_err(|e| Error::Msg(e.to_string()))?;
        inner.closed = true;
        if let Some(waker) = inner.waker.take() {
            waker.wake();
        }
        Ok(())
    }

    pub async fn push_chunk(&self, chunk: Vec<u8>) -> Result<(), Error> {
        let mut inner = self.inner.lock().map_err(|e| Error::Msg(e.to_string()))?;
        if inner.closed {
            return Err(Error::Msg("Buffer closed".into()));
        }
        inner.buffer.extend_from_slice(&chunk);
        if let Some(waker) = inner.waker.take() {
            waker.wake();
        }
        Ok(())
    }
}

impl AsyncRead for ChunkedBuffer {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        if inner.buffer.is_empty() && !inner.closed {
            inner.waker = Some(cx.waker().clone());
            return std::task::Poll::Pending;
        } else if inner.buffer.is_empty() && inner.closed {
            return std::task::Poll::Ready(Ok(()));
        }
        let to_read = std::cmp::min(buf.remaining(), inner.buffer.len());
        buf.put_slice(&inner.buffer[..to_read]);
        inner.buffer.drain(..to_read);
        debug!("ChunkedBuffer read: {}", to_read);
        std::task::Poll::Ready(Ok(()))
    }
}

#[derive(uniffi::Object)]
pub struct App {
    url: String,
    name: String,
    app_key: PrivateKey,
    description: String,

    sdk: Mutex<Option<Arc<SDK<ConnectedState>>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl App {
    #[uniffi::constructor]
    pub fn new(
        url: String,
        name: String,
        app_seed: Vec<u8>,
        description: String,
    ) -> Result<Self, Error> {
        debug!("app called");
        let app_seed: [u8; 32] = app_seed
            .try_into()
            .map_err(|_| Error::Msg("App seed must be 32 bytes".into()))?;
        let app_seed = PrivateKey::from_seed(&app_seed);
        debug!("app seed inited");
        Ok(Self {
            url,
            name,
            app_key: app_seed,
            description,

            sdk: Mutex::new(None),
        })
    }

    pub async fn connect(&self) -> Result<(), Error> {
        let client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        let connected_sdk = SDK::connect(
            &self.url,
            self.app_key.clone(),
            self.name.clone(),
            self.description.clone(),
            self.url.parse().unwrap(),
        )
        .await
        .map_err(|e| Error::Msg(e.to_string()))?
        .connected(client_crypto)
        .await
        .map_err(|e| Error::Msg(e.to_string()))?;
        let mut sdk = self.sdk.lock().map_err(|e| Error::Msg(e.to_string()))?;
        *sdk = Some(Arc::new(connected_sdk));
        Ok(())
    }

    pub async fn upload(
        &self,
        encryption_key: Vec<u8>,
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Upload, Error> {
        let encryption_key: [u8; 32] = encryption_key
            .try_into()
            .map_err(|_| Error::Msg("Encryption key must be 32 bytes".into()))?;
        let buf = ChunkedBuffer::new();
        let sdk = {
            let sdk_lock = self.sdk.lock().map_err(|e| Error::Msg(e.to_string()))?;
            sdk_lock
                .as_ref()
                .ok_or_else(|| Error::Msg("SDK not connected".into()))?
                .clone()
        };
        debug!("starting upload");
        let inner_buf = buf.clone();
        let (tx, rx) = oneshot::channel();
        debug!("inited buf");
        let result = tokio::spawn(async move {
            debug!("task started");
            let res = sdk
                .upload(inner_buf, encryption_key, data_shards, parity_shards)
                .await
                .map_err(|e| Error::Msg(e.to_string()));
            let _ = tx.send(res);
        });
        debug!("spawned upload task");
        Ok(Upload {
            reader: buf.clone(),
            result,
            rx: tokio::sync::Mutex::new(Some(rx)),
        })
    }
}

#[derive(uniffi::Object)]
pub struct Slab {
    pub id: String,
    pub offset: usize,
    pub length: usize,
}

#[derive(uniffi::Object)]
pub struct Upload {
    reader: ChunkedBuffer,
    result: JoinHandle<()>,
    rx: tokio::sync::Mutex<Option<oneshot::Receiver<Result<Vec<PinnedSlab>, Error>>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Upload {
    pub async fn write(&self, buf: &[u8]) -> Result<(), Error> {
        if self.result.is_finished() {
            return Err(Error::Msg("Upload already completed".into()));
        }
        self.reader.push_chunk(buf.to_vec()).await?;
        debug!("pushed chunk");
        Ok(())
    }

    pub async fn finish(&self) -> Result<(), Error> {
        debug!("finishing upload");
        self.reader.close()?;
        let rx = self.rx.lock().await.take().unwrap();
        let slabs = rx.await.map_err(|e| Error::Msg(e.to_string()))??;
        debug!("file uploaded {}", slabs[0].id);
        Ok(())
    }
}

#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}
