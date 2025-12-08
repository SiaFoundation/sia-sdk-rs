uniffi::setup_scaffolding!();

use base64::prelude::*;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::SystemTime;
use tokio::runtime::{self, Runtime};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use indexd::{Object, SealedObjectError, Url, quic};
use log::debug;
use sia::rhp::SECTOR_SIZE;
use sia::signing::{PublicKey, Signature};
use sia::types::{self, Hash256, HexParseError};
use sia::{encoding, encryption};
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::JoinHandle;

mod tls;

mod logging;
pub use logging::*;

mod builder;
pub use builder::*;

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create global runtime")
});

/// A helper that spawns a future onto the global runtime and returns an AbortOnDropHandle
/// to ensure cancellation works with Uniffi.
fn spawn<F, T>(future: F) -> AbortOnDropHandle<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    AbortOnDropHandle::new(RUNTIME.spawn(future))
}

#[uniffi::export(with_foreign)]
pub trait UploadProgressCallback: Send + Sync {
    fn progress(&self, uploaded: u64, encoded_size: u64);
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum Error {
    #[error("{0}")]
    SDK(#[from] indexd::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("app error: {0}")]
    AppClient(#[from] indexd::app_client::Error),

    #[error("quic error: {0}")]
    Quic(#[from] indexd::quic::Error),

    #[error("hex error: {0}")]
    HexParseError(#[from] sia::types::HexParseError),

    #[error("not connected")]
    NotConnected,

    #[error("sealed object error: {0}")]
    SealedObject(#[from] SealedObjectError),

    #[error("task error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("error: {0}")]
    Custom(String),
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum ConnectError {
    #[error("not connected")]
    NotConnected,
    #[error("already connected")]
    AlreadyConnected,
    #[error("app client error: {0}")]
    AppClient(#[from] indexd::app_client::Error),
    #[error("task error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("error: {0}")]
    Custom(String),
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum UploadError {
    #[error("buffer closed")]
    Closed,

    #[error("{0}")]
    Upload(#[from] indexd::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("not connected")]
    NotConnected,

    #[error("task error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("custom error: {0}")]
    Custom(String),
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum DownloadError {
    #[error("{0}")]
    SDK(#[from] indexd::Error),

    #[error("app error: {0}")]
    AppClient(#[from] indexd::app_client::Error),

    #[error("hex error: {0}")]
    HexParseError(#[from] sia::types::HexParseError),

    #[error("not connected")]
    NotConnected,

    #[error("cancelled")]
    Cancelled,

    #[error("task error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("custom error: {0}")]
    Custom(String),
}

struct ChunkedWriterInner {
    buffer: Vec<u8>,
    rx: Receiver<Vec<u8>>,
    tx: Option<Sender<Vec<u8>>>,
}

#[derive(Clone)]
struct ChunkedWriter {
    inner: Arc<Mutex<ChunkedWriterInner>>,
}

impl ChunkedWriter {
    pub fn close(&self) -> Result<(), UploadError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| UploadError::Custom(e.to_string()))?;
        inner.tx.take();
        Ok(())
    }

    pub async fn push_chunk(&self, chunk: Vec<u8>) -> Result<(), UploadError> {
        let tx = {
            let inner = self
                .inner
                .lock()
                .map_err(|e| UploadError::Custom(e.to_string()))?;
            match inner.tx.clone() {
                Some(tx) => tx,
                None => return Err(UploadError::Closed),
            }
        };
        tx.send(chunk)
            .await
            .map_err(|e| UploadError::Custom(format!("failed to send chunk to reader: {}", e)))
    }
}

impl Default for ChunkedWriter {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel(1);
        Self {
            inner: Arc::new(Mutex::new(ChunkedWriterInner {
                buffer: Vec::with_capacity(SECTOR_SIZE),
                rx,
                tx: Some(tx),
            })),
        }
    }
}

impl AsyncRead for ChunkedWriter {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        if !inner.buffer.is_empty() {
            let to_read = buf.remaining().min(inner.buffer.len());
            buf.put_slice(&inner.buffer[..to_read]);
            inner.buffer.drain(..to_read); // remove the read bytes
            return std::task::Poll::Ready(Ok(()));
        }

        match inner.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(chunk)) => {
                let to_read = buf.remaining().min(chunk.len());
                buf.put_slice(&chunk[..to_read]);
                if to_read < chunk.len() {
                    // save the rest for the next call
                    inner.buffer.extend_from_slice(&chunk[to_read..]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())), // channel closed
            std::task::Poll::Pending => std::task::Poll::Pending,           // no data available yet
        }
    }
}

/// Metadata about an application connecting to the indexer.
#[derive(uniffi::Record)]
pub struct AppMeta {
    pub id: Vec<u8>,
    pub name: String,
    pub description: String,
    pub service_url: String,
    pub logo_url: Option<String>,
    pub callback_url: Option<String>,
}

/// The protocol used in a network address.
#[derive(uniffi::Enum)]
pub enum AddressProtocol {
    SiaMux,
    Quic,
}

/// A network address of a storage provider on the Sia network.
#[derive(uniffi::Record)]
pub struct NetAddress {
    pub protocol: AddressProtocol,
    pub address: String,
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum EncryptionKeyParseError {
    #[error("failed to decode base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid key length: {0}, expected 32 bytes")]
    KeyLength(usize),
}

#[derive(uniffi::Object)]
pub struct EncryptionKey(encryption::EncryptionKey);

#[uniffi::export]
impl EncryptionKey {
    #[uniffi::constructor]
    pub fn parse(str: String) -> Result<Self, EncryptionKeyParseError> {
        let data = BASE64_STANDARD.decode(str.as_bytes())?;
        if data.len() != 32 {
            return Err(EncryptionKeyParseError::KeyLength(data.len()));
        }
        Ok(Self(encryption::EncryptionKey::from(
            <[u8; 32]>::try_from(data).unwrap(),
        )))
    }

    /// Exports the key as a base64 encoded string.
    ///
    /// This should be used to store the key securely.
    /// The key should never be shared or transmitted
    /// in plaintext.
    pub fn export(&self) -> String {
        BASE64_STANDARD.encode(self.0.as_ref())
    }
}

impl From<encryption::EncryptionKey> for EncryptionKey {
    fn from(key: encryption::EncryptionKey) -> Self {
        Self(key)
    }
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum ObjectError {
    #[error("sealed object error: {0}")]
    SealedObject(#[from] SealedObjectError),

    #[error("encoding error: {0}")]
    Encoding(#[from] encoding::Error),
}

/// An object that has been pinned to an indexer. Objects are immutable
/// data stored on the Sia network. The data is erasure-coded and distributed across
/// multiple storage providers. The object is encrypted with a unique encryption key,
/// which is used to encrypt the metadata.
///
/// Custom user-defined metadata can be associated with the object. It is
/// recommended to use a portable format like JSON for metadata.
///
/// It can be sealed for secure offline storage or transmission and
/// later opened using the app key.
///
/// It has no public fields to prevent accidental leakage or corruption.
#[derive(uniffi::Object)]
pub struct PinnedObject {
    inner: Arc<Mutex<indexd::Object>>,
}

impl PinnedObject {
    fn object(&self) -> indexd::Object {
        self.inner.lock().unwrap().clone()
    }
}

#[uniffi::export]
impl PinnedObject {
    /// Opens a sealed object using the provided app key.
    ///
    /// # Arguments
    /// * `app_key` - The app key that was used to seal the object.
    /// * `sealed` - The sealed object to open.
    ///
    /// # Returns
    /// The unsealed object or an error if the object could not be opened.
    #[uniffi::constructor]
    pub fn open(app_key: Arc<AppKey>, sealed: SealedObject) -> Result<Self, ObjectError> {
        let sealed = indexd::SealedObject {
            encrypted_master_key: sealed.encrypted_master_key,
            slabs: sealed
                .slabs
                .into_iter()
                .map(|s| s.try_into().unwrap())
                .collect(),
            encrypted_metadata: Some(sealed.encrypted_metadata),
            signature: Signature::try_from(sealed.signature.as_ref())?,
            created_at: sealed.created_at.into(),
            updated_at: sealed.updated_at.into(),
        };
        let obj = sealed.open(app_key.private_key())?;
        Ok(Self {
            inner: Arc::new(Mutex::new(obj)),
        })
    }

    /// Seal the object for offline storage.
    /// # Arguments
    /// * `app_key` - The app key used to derive the master key to encrypt the object's encryption key.
    ///
    /// # Returns
    /// The sealed object.
    pub fn seal(&self, app_key: Arc<AppKey>) -> SealedObject {
        let inner = self.inner.lock().unwrap();
        SealedObject::from(inner.seal(app_key.private_key()))
    }

    /// Returns the object's ID, which is the Blake2b hash of its slabs.
    pub fn id(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.id().to_string()
    }

    /// Returns the total size of the object by summing the lengths of its slabs.
    pub fn size(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.slabs.iter().fold(0_u64, |v, s| v + s.length as u64)
    }

    /// Returns the slabs that make up the object.
    pub fn slabs(&self) -> Vec<Slab> {
        let inner = self.inner.lock().unwrap();
        inner.slabs.iter().cloned().map(|s| s.into()).collect()
    }

    /// Returns the metadata associated with the object.
    pub fn metadata(&self) -> Vec<u8> {
        let inner = self.inner.lock().unwrap();
        inner.metadata.clone()
    }

    /// Updates the metadata associated with the object.
    pub fn update_metadata(&self, metadata: Vec<u8>) {
        let mut inner = self.inner.lock().unwrap();
        inner.metadata = metadata;
    }

    /// Returns the time the object was created.
    pub fn created_at(&self) -> SystemTime {
        let inner = self.inner.lock().unwrap();
        inner.created_at.into()
    }

    /// Returns the time the object was last updated.
    pub fn updated_at(&self) -> SystemTime {
        let inner = self.inner.lock().unwrap();
        inner.updated_at.into()
    }
}

/// A sealed object represents an object that has been encrypted
/// for secure offline storage or processing. It can be opened using
/// an app key to retrieve the original object.
#[derive(uniffi::Record)]
pub struct SealedObject {
    pub id: String,
    pub encrypted_master_key: Vec<u8>,
    pub slabs: Vec<Slab>,
    pub encrypted_metadata: Vec<u8>,
    pub signature: Vec<u8>,

    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

impl From<indexd::SealedObject> for SealedObject {
    fn from(o: indexd::SealedObject) -> Self {
        Self {
            id: o.id().to_string(),
            encrypted_master_key: o.encrypted_master_key,
            slabs: o.slabs.into_iter().map(|s| s.into()).collect(),
            encrypted_metadata: o.encrypted_metadata.unwrap_or_default(),
            signature: o.signature.as_ref().to_vec(),
            created_at: o.created_at.into(),
            updated_at: o.updated_at.into(),
        }
    }
}

impl TryInto<indexd::SealedObject> for SealedObject {
    type Error = SealedObjectError;

    fn try_into(self) -> Result<indexd::SealedObject, Self::Error> {
        let sealed = indexd::SealedObject {
            encrypted_master_key: self.encrypted_master_key,
            slabs: self
                .slabs
                .into_iter()
                .map(|s| s.try_into().unwrap())
                .collect(),
            encrypted_metadata: Some(self.encrypted_metadata),
            signature: Signature::try_from(self.signature.as_ref())?,
            created_at: self.created_at.into(),
            updated_at: self.updated_at.into(),
        };
        if sealed.id().to_string() != self.id {
            return Err(SealedObjectError::ContentsMismatch);
        }
        Ok(sealed)
    }
}

/// An ObjectEvent represents an object and whether it was deleted or not.
#[derive(uniffi::Record)]
pub struct ObjectEvent {
    pub key: String,
    pub deleted: bool,
    pub updated_at: SystemTime,
    pub object: Option<Arc<PinnedObject>>,
}

/// An object that has been shared from an indexer. Shared objects
/// are read-only and cannot be modified. They can be downloaded
/// using [Sdk.download_shared] or pinned using [Sdk.pin_shared].
///
/// It has no public fields to prevent accidental leakage or corruption.
#[derive(uniffi::Object)]
pub struct SharedObject(indexd::SharedObject);

#[uniffi::export]
impl SharedObject {
    /// Returns the size of the object by summing the lengths of its slabs.
    pub fn size(&self) -> u64 {
        self.0.size()
    }

    /// Returns the slabs that make up the object.
    pub fn metadata(&self) -> Vec<u8> {
        self.0.metadata()
    }
}

/// Information about a storage provider on the
/// Sia network.
#[derive(uniffi::Record)]
pub struct Host {
    pub public_key: String,
    pub addresses: Vec<NetAddress>,
    pub country_code: String,
    pub latitude: f64,
    pub longitude: f64,
}

impl From<sia::rhp::Host> for Host {
    fn from(h: sia::rhp::Host) -> Self {
        Self {
            public_key: h.public_key.to_string(),
            addresses: h
                .addresses
                .iter()
                .map(|a| NetAddress {
                    protocol: match a.protocol {
                        types::v2::Protocol::SiaMux => AddressProtocol::SiaMux,
                        types::v2::Protocol::QUIC => AddressProtocol::Quic,
                    },
                    address: a.address.clone(),
                })
                .collect(),
            country_code: h.country_code,
            latitude: h.latitude,
            longitude: h.longitude,
        }
    }
}

impl TryInto<sia::rhp::Host> for Host {
    type Error = HexParseError;

    fn try_into(self) -> Result<sia::rhp::Host, Self::Error> {
        Ok(sia::rhp::Host {
            public_key: PublicKey::from_str(self.public_key.as_str())?,
            addresses: self
                .addresses
                .into_iter()
                .map(|a| {
                    Ok(types::v2::NetAddress {
                        protocol: match a.protocol {
                            AddressProtocol::SiaMux => types::v2::Protocol::SiaMux,
                            AddressProtocol::Quic => types::v2::Protocol::QUIC,
                        },
                        address: a.address,
                    })
                })
                .collect::<Result<Vec<types::v2::NetAddress>, HexParseError>>()?,
            country_code: self.country_code,
            latitude: self.latitude,
            longitude: self.longitude,
        })
    }
}

/// A sector stored on a specific host.
#[derive(Clone, uniffi::Record)]
pub struct PinnedSector {
    pub root: String,
    pub host_key: String,
}

/// A PinnedSlab represents a slab that has been pinned to the indexer.
#[derive(uniffi::Record)]
pub struct PinnedSlab {
    pub id: String,
    pub encryption_key: Vec<u8>,
    pub min_shards: u8,
    pub sectors: Vec<PinnedSector>,
}

impl From<indexd::PinnedSlab> for PinnedSlab {
    fn from(s: indexd::PinnedSlab) -> Self {
        Self {
            id: s.id.to_string(),
            encryption_key: s.encryption_key.as_ref().to_vec(),
            min_shards: s.min_shards,
            sectors: s
                .sectors
                .into_iter()
                .map(|sec| PinnedSector {
                    root: sec.root.to_string(),
                    host_key: sec.host_key.to_string(),
                })
                .collect(),
        }
    }
}

/// A Slab represents a contiguous erasure-coded segment of a file stored on the Sia network.
#[derive(uniffi::Record)]
pub struct Slab {
    pub encryption_key: Vec<u8>,
    pub min_shards: u8,
    pub sectors: Vec<PinnedSector>,
    pub offset: u32,
    pub length: u32,
}

impl From<indexd::Slab> for Slab {
    fn from(s: indexd::Slab) -> Self {
        Self {
            encryption_key: s.encryption_key.as_ref().to_vec(),
            min_shards: s.min_shards,
            sectors: s
                .sectors
                .into_iter()
                .map(|sec| PinnedSector {
                    root: sec.root.to_string(),
                    host_key: sec.host_key.to_string(),
                })
                .collect(),
            offset: s.offset,
            length: s.length,
        }
    }
}

impl TryInto<indexd::Slab> for Slab {
    type Error = String;

    fn try_into(self) -> Result<indexd::Slab, Self::Error> {
        Ok(indexd::Slab {
            encryption_key: encryption::EncryptionKey::try_from(self.encryption_key.as_slice())?,
            min_shards: self.min_shards,
            sectors: self
                .sectors
                .into_iter()
                .map(|sec| sec.try_into())
                .collect::<Result<Vec<indexd::Sector>, HexParseError>>()
                .map_err(|e| e.to_string())?,
            offset: self.offset,
            length: self.length,
        })
    }
}

impl TryInto<indexd::Sector> for PinnedSector {
    type Error = HexParseError;

    fn try_into(self) -> Result<indexd::Sector, Self::Error> {
        Ok(indexd::Sector {
            host_key: PublicKey::from_str(self.host_key.as_str())?,
            root: Hash256::from_str(self.root.as_str())?,
        })
    }
}

/// Used to paginate through objects stored in the indexer.
///
/// When syncing changes from an indexer, `after` should be set to the
/// last `updated_at` timestamp seen, and `key` should be set to the
/// last object's key seen.
#[derive(uniffi::Record)]
pub struct ObjectsCursor {
    pub after: SystemTime,
    pub key: String,
}

impl From<indexd::app_client::ObjectsCursor> for ObjectsCursor {
    fn from(c: indexd::app_client::ObjectsCursor) -> Self {
        Self {
            after: c.after.into(),
            key: c.key.to_string(),
        }
    }
}

/// An account registered on the indexer.
#[derive(uniffi::Record)]
pub struct Account {
    pub account_key: String,
    pub service_account: bool,
    pub max_pinned_data: u64,
    pub pinned_data: u64,
    pub description: String,
    pub logo_url: Option<String>,
    pub service_url: Option<String>,
}

impl From<indexd::app_client::Account> for Account {
    fn from(a: indexd::app_client::Account) -> Self {
        Self {
            account_key: a.account_key.to_string(),
            service_account: a.service_account,
            max_pinned_data: a.max_pinned_data,
            pinned_data: a.pinned_data,
            description: a.description,
            logo_url: a.logo_url,
            service_url: a.service_url,
        }
    }
}

/// Provides options for an upload operation.
#[derive(uniffi::Record)]
pub struct UploadOptions {
    #[uniffi(default = 10)]
    pub max_inflight: u8,
    #[uniffi(default = 10)]
    pub data_shards: u8,
    #[uniffi(default = 20)]
    pub parity_shards: u8,

    /// Optional metadata to attach to the object.
    /// This will be encrypted with the object's master key.
    #[uniffi(default = None)]
    pub metadata: Option<Vec<u8>>,
    /// Optional callback to report upload progress.
    /// The callback will be called with the number of bytes uploaded
    /// and the total encoded size of the upload.
    #[uniffi(default = None)]
    pub progress_callback: Option<Arc<dyn UploadProgressCallback>>,
}

/// Provides options for a download operation.
#[derive(uniffi::Record)]
pub struct DownloadOptions {
    #[uniffi(default = 10)]
    pub max_inflight: u8,
    #[uniffi(default = 0)]
    pub offset: u64,
    #[uniffi(default = None)]
    pub length: Option<u64>,
}

#[derive(uniffi::Object)]
pub struct SDK {
    inner: indexd::SDK,
}

#[uniffi::export]
impl SDK {
    /// Returns the application key used by the SDK.
    ///
    /// This should be kept secret and secure. Applications
    /// must never share their app key publicly. Store
    /// it safely.
    pub fn app_key(&self) -> AppKey {
        AppKey::from(self.inner.app_key().clone())
    }

    /// Uploads data to the Sia network and pins it to the indexer
    ///
    /// # Warnings
    /// * The `encryption_key` must be unique for every upload. Reusing an
    ///   encryption key will compromise the security of the data.
    ///
    /// # Returns
    /// An object representing the uploaded data.
    pub async fn upload(&self, options: UploadOptions) -> Result<Upload, UploadError> {
        let sdk = self.inner.clone();
        // do not use helper, use cancellation token directly
        RUNTIME
            .spawn(async move {
                let buf = ChunkedWriter::default();
                let progress_tx = if let Some(callback) = options.progress_callback {
                    let total_shards = options.data_shards as u64 + options.parity_shards as u64;
                    let slab_size = total_shards * SECTOR_SIZE as u64;
                    let (tx, mut rx) = mpsc::unbounded_channel();
                    tokio::spawn(async move {
                        let mut sectors: u64 = 0;
                        while rx.recv().await.is_some() {
                            sectors += 1;
                            let size = sectors * SECTOR_SIZE as u64;
                            let slabs_size = sectors.div_ceil(total_shards) * slab_size;
                            callback.progress(size, slabs_size);
                        }
                    });
                    Some(tx)
                } else {
                    None
                };

                let cancel_token = CancellationToken::new();
                let upload_token = cancel_token.child_token();
                let result_buf = buf.clone();
                let result = tokio::spawn(async move {
                    let res = sdk
                        .upload(
                            upload_token,
                            result_buf,
                            quic::UploadOptions {
                                max_inflight: options.max_inflight as usize,
                                data_shards: options.data_shards,
                                parity_shards: options.parity_shards,
                                metadata: options.metadata,
                                shard_uploaded: progress_tx,
                            },
                        )
                        .await?;
                    Ok(res)
                });
                Ok(Upload {
                    reader: buf.clone(),
                    result: Mutex::new(Some(result)),
                    cancel: cancel_token,
                })
            })
            .await?
    }

    /// Initiates a download of the data referenced by the object, starting at `offset` and reading `length` bytes.
    ///
    /// # Returns
    /// A [Download] object that can be used to read the data in chunks
    pub async fn download(
        &self,
        object: Arc<PinnedObject>,
        options: DownloadOptions,
    ) -> Result<Download, DownloadError> {
        const CHUNK_SIZE: usize = 1 << 19; // 512KiB
        let object = object.object();
        let object_size = object.size();
        let offset = options.offset as usize;
        let total_length = options.length.unwrap_or(object_size) as usize;
        let max_inflight = options.max_inflight;
        let (chunk_tx, chunk_rx) = mpsc::channel(8); // 4MiB buffer
        let cancel_token = CancellationToken::new();
        let future_token = cancel_token.child_token();
        let sdk = self.inner.clone();
        // do not use helper, use cancellation token directly
        RUNTIME.spawn(async move {
            for offset in (offset..total_length).step_by(CHUNK_SIZE) {
                let mut buf = Vec::with_capacity(CHUNK_SIZE);
                let future = sdk.download(
                    &mut buf,
                    &object,
                    quic::DownloadOptions {
                        offset,
                        length: Some(total_length.min(CHUNK_SIZE)),
                        max_inflight: max_inflight as usize,
                    },
                );
                select! {
                    _ = future_token.cancelled() => {
                        chunk_tx.send(Err(DownloadError::Cancelled)).await.ok();
                        return;
                    },
                    result = future => {
                        let n = buf.len();
                        let result = result
                            .map(|_| buf)
                            .map_err(DownloadError::from)
                            .inspect(|_| { debug!("downloaded chunk {}-{}", offset, offset+n) });
                        chunk_tx.send(result).await.ok();
                    }
                }
            }
        });
        Ok(Download {
            cancel_token,
            rx: tokio::sync::Mutex::new(chunk_rx),
        })
    }

    /// Initiates a download of the data referenced by the shared object, starting at `offset` and reading `length` bytes.
    ///
    /// # Returns
    /// A [`Download`] object that can be used to read the data in chunks
    pub async fn download_shared(
        &self,
        shared_object: Arc<SharedObject>,
        options: DownloadOptions,
    ) -> Result<Download, DownloadError> {
        const CHUNK_SIZE: usize = 1 << 19; // 512KiB
        let shared_object = shared_object.0.clone();
        let object_size = shared_object.size();
        let offset = options.offset as usize;
        let total_length = options.length.unwrap_or(object_size) as usize;
        let max_inflight = options.max_inflight;
        let (chunk_tx, chunk_rx) = mpsc::channel(8); // 4MiB buffer
        let cancel_token = CancellationToken::new();
        let future_token = cancel_token.child_token();
        let sdk = self.inner.clone();
        // do not use helper, use cancellation token directly
        RUNTIME.spawn(async move {
            for offset in (offset..total_length).step_by(CHUNK_SIZE) {
                let mut buf = Vec::with_capacity(CHUNK_SIZE);
                let future = sdk.download_shared(
                    &mut buf,
                    &shared_object,
                    quic::DownloadOptions {
                        offset,
                        length: Some(total_length.min(CHUNK_SIZE)),
                        max_inflight: max_inflight as usize,
                    },
                );
                select! {
                    _ = future_token.cancelled() => {
                        chunk_tx.send(Err(DownloadError::Cancelled)).await.ok();
                        return;
                    },
                    result = future => {
                        let result = result
                            .map(|_| buf)
                            .map_err(DownloadError::from);
                        chunk_tx.send(result).await.ok();
                    }
                }
            }
        });
        Ok(Download {
            cancel_token,
            rx: tokio::sync::Mutex::new(chunk_rx),
        })
    }

    /// Returns a list of all usable hosts.
    pub async fn hosts(&self) -> Result<Vec<Host>, Error> {
        let sdk = self.inner.clone();
        spawn(async move {
            let hosts = sdk.hosts(Default::default()).await?;
            Ok(hosts.into_iter().map(|h| h.into()).collect())
        })
        .await?
    }

    /// Returns objects stored in the indexer. When syncing, the caller should
    /// provide the last `updated_at` timestamp and `key` seen in the `cursor
    /// parameter to avoid missing or duplicating objects.
    ///
    /// # Arguments
    /// * `cursor` can be used to paginate through the results. If `cursor` is `None`, the first page of results will be returned.
    /// * `limit` specifies the maximum number of objects to return.
    pub async fn object_events(
        &self,
        cursor: Option<ObjectsCursor>,
        limit: u32,
    ) -> Result<Vec<ObjectEvent>, Error> {
        let cursor = match cursor {
            Some(c) => Some(indexd::app_client::ObjectsCursor {
                after: c.after.into(),
                key: Hash256::from_str(c.key.as_str())?,
            }),
            None => None,
        };
        let sdk = self.inner.clone();
        spawn(async move {
            let objects = sdk
                .object_events(cursor, Some(limit as usize))
                .await?
                .into_iter()
                .map(|event| {
                    Ok(ObjectEvent {
                        key: event.key.to_string(),
                        deleted: event.deleted,
                        updated_at: event.updated_at.into(),
                        object: event.object.map(|obj| {
                            Arc::new(PinnedObject {
                                inner: Arc::new(Mutex::new(obj)),
                            })
                        }),
                    })
                })
                .collect::<Result<Vec<ObjectEvent>, SealedObjectError>>()?;
            Ok(objects)
        })
        .await?
    }

    /// Saves an object to the indexer.
    pub async fn save_object(&self, object: Arc<PinnedObject>) -> Result<(), Error> {
        let object = object.object();
        let sdk = self.inner.clone();
        spawn(async move {
            sdk.save_object(&object).await?;
            Ok(())
        })
        .await?
    }

    /// Deletes an object from the indexer.
    pub async fn delete_object(&self, key: String) -> Result<(), Error> {
        let key = Hash256::from_str(key.as_str())?;
        let sdk = self.inner.clone();
        spawn(async move {
            sdk.delete_object(&key).await?;
            Ok(())
        })
        .await?
    }

    /// Returns metadata about a specific object stored in the indexer.
    pub async fn object(&self, key: String) -> Result<PinnedObject, Error> {
        let key = Hash256::from_str(key.as_str())?;
        let sdk = self.inner.clone();
        spawn(async move {
            let obj = sdk.object(&key).await?;
            Ok(PinnedObject {
                inner: Arc::new(Mutex::new(obj)),
            })
        })
        .await?
    }

    /// Returns metadata about a slab stored in the indexer.
    pub async fn slab(&self, slab_id: String) -> Result<PinnedSlab, Error> {
        let slab_id = Hash256::from_str(slab_id.as_str())?;
        let sdk = self.inner.clone();
        spawn(async move {
            let slab = sdk.slab(&slab_id).await?;
            Ok(slab.into())
        })
        .await?
    }

    /// Unpins slabs not used by any object on the account.
    pub async fn prune_slabs(&self) -> Result<(), Error> {
        let sdk = self.inner.clone();
        spawn(async move {
            sdk.prune_slabs().await?;
            Ok(())
        })
        .await?
    }

    /// Returns the current account.
    pub async fn account(&self) -> Result<Account, Error> {
        let sdk = self.inner.clone();
        spawn(async move {
            let account = sdk.account().await?;
            Ok(account.into())
        })
        .await?
    }

    /// Creates a signed URL that can be used to share object metadata
    /// with other people using an indexer.
    pub fn share_object(
        &self,
        object: Arc<PinnedObject>,
        valid_until: SystemTime,
    ) -> Result<String, Error> {
        let u = self
            .inner
            .share_object(&object.object(), valid_until.into())?;
        Ok(u.to_string())
    }

    /// Retrieves a shared object from a signed URL.
    pub async fn shared_object(&self, shared_url: &str) -> Result<SharedObject, Error> {
        let shared_url: Url = shared_url
            .parse()
            .map_err(|e| Error::Custom(format!("{e}")))?;
        let sdk = self.inner.clone();
        spawn(async move {
            let shared_object = sdk.shared_object(shared_url).await?;
            Ok(SharedObject(shared_object))
        })
        .await?
    }

    /// Pins a shared object to the indexer and returns a [PinnedObject].
    pub async fn pin_shared(&self, shared: Arc<SharedObject>) -> Result<PinnedObject, Error> {
        let shared_object = shared.0.clone();
        let sdk = self.inner.clone();
        spawn(async move {
            let obj = sdk.pin_shared(shared_object).await?;
            Ok(PinnedObject {
                inner: Arc::new(Mutex::new(obj)),
            })
        })
        .await?
    }
}

/// Uploads data to the Sia network. It does so in chunks to support large files in
/// arbitrary languages.
///
/// Callers should write data using [`Upload::write`] until EoF, then call
/// [`Upload::finalize`] to complete the upload and get the metadata. [`Upload::cancel`]
/// can be called to abort an in-progress upload.
///
/// Language bindings should provide a higher-level implementation that wraps a stream.
#[derive(uniffi::Object)]
pub struct Upload {
    reader: ChunkedWriter,
    result: Mutex<Option<JoinHandle<Result<Object, UploadError>>>>,
    cancel: CancellationToken,
}

impl Drop for Upload {
    fn drop(&mut self) {
        self.cancel();
        let _ = self.result.lock().unwrap().take(); // drop the result
    }
}

#[uniffi::export]
impl Upload {
    /// Writes a chunk of data to the Sia network. The data will be
    /// erasure-coded and encrypted before upload.
    ///
    /// Chunks should be written until EoF, then call [`Upload::finalize`].
    pub async fn write(&self, buf: &[u8]) -> Result<(), UploadError> {
        self.reader.push_chunk(buf.to_vec()).await
    }

    /// Cancels an in-progress upload. This will drop any data
    /// that has already been written.
    pub fn cancel(&self) {
        self.cancel.cancel(); // signal cancellation
        let _ = self.reader.close(); // ignore error

        let result = self.result.lock().unwrap().take();
        if let Some(result) = result {
            result.abort();
        }
    }

    /// Waits for all chunks of data to be pinned to the indexer and
    /// returns the metadata. Data can no longer be written after
    /// calling finalize. This function must only be called once.
    ///
    /// The caller must store the metadata locally in order to download
    /// it in the future.
    pub async fn finalize(&self) -> Result<PinnedObject, UploadError> {
        self.reader.close()?;
        let result = {
            let mut result = self.result.lock().unwrap();
            result.take()
        };
        match result {
            Some(result) => {
                let object = result.await??;
                Ok(PinnedObject {
                    inner: Arc::new(Mutex::new(object)),
                })
            }
            None => Err(UploadError::Closed),
        }
    }
}

/// Downloads data from the Sia network. It does so in chunks to support large files in
/// arbitrary languages.
///
/// Language bindings should provide a higher-level implementation that wraps a stream.
#[derive(uniffi::Object)]
pub struct Download {
    cancel_token: CancellationToken,
    rx: tokio::sync::Mutex<Receiver<Result<Vec<u8>, DownloadError>>>,
}

impl Drop for Download {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[uniffi::export]
impl Download {
    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    /// Reads a chunk of data from the Sia network.
    ///
    /// # Returns
    /// A vector containing the chunk of data read. If the vector is empty, the end of the download has been reached.
    pub async fn read_chunk(&self) -> Result<Vec<u8>, DownloadError> {
        if self.cancel_token.is_cancelled() {
            return Err(DownloadError::Cancelled);
        }
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(res) => res,
            None => Ok(Vec::with_capacity(0)),
        }
    }
}

/// Calculates the encoded size of data given the original size and erasure coding parameters.
#[uniffi::export]
pub fn encoded_size(size: u64, data_shards: u8, parity_shards: u8) -> u64 {
    let total_shards = data_shards as u64 + parity_shards as u64;
    let slab_size = total_shards * SECTOR_SIZE as u64;
    let slabs = size.div_ceil(data_shards as u64 * SECTOR_SIZE as u64);
    slabs * slab_size
}
