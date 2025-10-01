uniffi::setup_scaffolding!();

use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use indexd::app_client::{
    Client as AppClient, RegisterAppRequest, SlabPinParams as AppSlabPinParams,
};
use indexd::quic::{Client as HostClient, Downloader, SlabFetcher, Uploader};
use indexd::{SlabSlice, Url, quic};
use log::debug;
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use sia::encryption::EncryptionKey;
use sia::rhp::SECTOR_SIZE;
use sia::signing::{PrivateKey, PublicKey};
use sia::types::{self, Hash256, HexParseError};
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::{OnceCell, oneshot};
use tokio::task::JoinHandle;

mod logging;
pub use logging::*;

#[uniffi::export(with_foreign)]
pub trait UploadProgressCallback: Send + Sync {
    fn progress(&self, uploaded: u64, encoded_size: u64);
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum Error {
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

    #[error("error: {0}")]
    Custom(String),
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum UploadError {
    #[error("buffer closed")]
    Closed,

    #[error("upload error: {0}")]
    Upload(#[from] indexd::quic::UploadError),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("not connected")]
    NotConnected,

    #[error("custom error: {0}")]
    Custom(String),
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum DownloadError {
    #[error("download error: {0}")]
    Download(#[from] indexd::quic::DownloadError),

    #[error("app error: {0}")]
    AppClient(#[from] indexd::app_client::Error),

    #[error("hex error: {0}")]
    HexParseError(#[from] sia::types::HexParseError),

    #[error("not connected")]
    NotConnected,

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

#[derive(uniffi::Record)]
pub struct PinnedObject {
    pub key: String,
    pub slabs: Vec<Slab>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,

    encrypted_metadata: Vec<u8>, // accessed via 'decrypt'
}

impl PinnedObject {
    /// Decrypts the metadata of an object and returns it.
    ///
    /// # Arguments
    /// * `key` - The 32-byte encryption key used when uploading the object.
    ///
    /// # Returns
    /// The decrypted metadata, or None if no metadata was provided.
    pub fn decrypt_metadata(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
        if self.encrypted_metadata.is_empty() {
            return Ok(None);
        }
        let encryption_key =
            EncryptionKey::try_from(key.as_ref()).map_err(|err| Error::Custom(err.to_string()))?;
        let encrypted_meta = indexd::EncryptedMetadata::from(self.encrypted_metadata.clone());
        let decrypted = encrypted_meta
            .decrypt(&encryption_key)
            .map_err(|err| Error::Custom(format!("failed to decrypt metadata: {}", err)))?;
        Ok(Some(decrypted))
    }

    /// Calculates the total size of the object by summing the lengths of its slabs.
    pub fn size(&self) -> u64 {
        self.slabs.iter().fold(0_u64, |v, s| v + s.length as u64)
    }
}

impl From<indexd::Object> for PinnedObject {
    fn from(o: indexd::Object) -> Self {
        Self {
            key: o.key.to_string(),
            slabs: o.slabs.into_iter().map(|s| s.into()).collect(),
            encrypted_metadata: o.meta.as_ref().into(),
            created_at: o.created_at.into(),
            updated_at: o.updated_at.into(),
        }
    }
}

impl TryInto<indexd::Object> for PinnedObject {
    type Error = HexParseError;

    fn try_into(self) -> Result<indexd::Object, Self::Error> {
        Ok(indexd::Object {
            key: Hash256::from_str(self.key.as_str())?,
            slabs: self
                .slabs
                .into_iter()
                .map(|s| s.try_into())
                .collect::<Result<Vec<SlabSlice>, HexParseError>>()?,
            meta: self.encrypted_metadata.into(),
            created_at: self.created_at.into(),
            updated_at: self.updated_at.into(),
        })
    }
}

/// UploadMeta represents an uploaded object and the metadata needed to
/// retrieve it.
#[derive(uniffi::Record)]
pub struct UploadMeta {
    pub encryption_key: Vec<u8>,
    pub object: PinnedObject,
}

impl From<indexd::UploadMeta> for UploadMeta {
    fn from(upload_meta: indexd::UploadMeta) -> Self {
        Self {
            encryption_key: upload_meta.encryption_key.as_ref().into(),
            object: upload_meta.object.into(),
        }
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
    pub id: String,
    pub offset: u32,
    pub length: u32,
}

impl From<SlabSlice> for Slab {
    fn from(s: SlabSlice) -> Self {
        Self {
            id: s.slab_id.to_string(),
            offset: s.offset as u32,
            length: s.length as u32,
        }
    }
}

impl TryInto<SlabSlice> for Slab {
    type Error = HexParseError;

    fn try_into(self) -> Result<SlabSlice, Self::Error> {
        Ok(SlabSlice {
            slab_id: Hash256::from_str(self.id.as_str())?,
            offset: self.offset as usize,
            length: self.length as usize,
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

#[derive(Clone, uniffi::Record)]
pub struct SlabPinParams {
    pub encryption_key: Vec<u8>,
    pub min_shards: u8,
    pub sectors: Vec<PinnedSector>,
}

impl TryInto<AppSlabPinParams> for SlabPinParams {
    type Error = Error;

    fn try_into(self) -> Result<AppSlabPinParams, Error> {
        Ok(AppSlabPinParams {
            encryption_key: EncryptionKey::try_from(self.encryption_key.as_ref())
                .map_err(|v| Error::Crypto(format!("failed to convert encryption key: {:?}", v)))?,
            min_shards: self.min_shards,
            sectors: self
                .sectors
                .into_iter()
                .map(|s| s.try_into())
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

/// The response from requesting app authorization.
///
/// The `response_url` is the URL the user should visit to authorize the app.
/// The `status_url` is the URL the app should poll to check if the user has
/// authorized the app.
#[derive(uniffi::Record)]
pub struct RequestAuthResponse {
    pub response_url: String,
    pub status_url: String,
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

/// A slab that has been shared via a share URL.
#[derive(uniffi::Record)]
pub struct SharedSlab {
    pub slab_id: String,
    pub encryption_key: Vec<u8>,
    pub min_shards: u8,
    pub sectors: Vec<PinnedSector>,
    pub offset: u32,
    pub length: u32,
}

/// An object that has been shared via a share URL.
#[derive(uniffi::Record)]
pub struct SharedObject {
    pub key: String,
    pub slabs: Vec<SharedSlab>,
    pub meta: Option<Vec<u8>>,
    pub encryption_key: Vec<u8>,
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

impl SharedObject {
    /// Calculates the total size of the object by summing the lengths of its slabs.
    pub fn size(&self) -> u64 {
        self.slabs.iter().fold(0_u64, |v, s| v + s.length as u64)
    }
}

/// Provides options for an upload operation.
#[derive(uniffi::Record)]
pub struct UploadOptions {
    pub max_inflight: u8,
    pub data_shards: u8,
    pub parity_shards: u8,
    pub progress_callback: Option<Arc<dyn UploadProgressCallback>>,
}

/// Provides options for a download operation.
#[derive(uniffi::Record)]
pub struct DownloadOptions {
    pub max_inflight: u8,
    pub offset: u64,
    pub length: Option<u64>,
}

/// An SDK enables interaction with an indexer and
/// storage providers on the Sia network.
#[derive(uniffi::Object)]
pub struct SDK {
    app_key: PrivateKey,
    app_client: AppClient,
    downloader: OnceCell<Arc<Downloader>>,
    uploader: OnceCell<Arc<Uploader>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl SDK {
    /// Creates a new SDK instance.
    ///
    /// # Arguments
    /// * `indexer_url` - The URL of the indexer to connect to.
    /// * `app_seed` - A 32-byte seed used to derive the app's private key.
    ///
    /// # Returns
    /// A new SDK instance.
    #[uniffi::constructor]
    pub fn new(indexer_url: String, app_seed: Vec<u8>) -> Result<Self, Error> {
        let app_seed: [u8; 32] = app_seed
            .try_into()
            .map_err(|_| Error::Custom("App seed must be 32 bytes".into()))?;
        let app_key = PrivateKey::from_seed(&app_seed);
        let app_client = AppClient::new(indexer_url, app_key.clone())?;

        Ok(Self {
            app_key,
            app_client: app_client.clone(),
            downloader: OnceCell::new(),
            uploader: OnceCell::new(),
        })
    }

    /// Returns true if the app key is authorized, returns false otherwise
    pub async fn connect(&self) -> Result<bool, Error> {
        let connected = self.app_client.check_app_authenticated().await?;
        if self.downloader.initialized() {
            return Ok(connected);
        }

        // install crypto provider
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .map_err(|e| Error::Crypto(format!("{:?}", e)))?;
        }

        // load root certs
        let rustls_config =
            ClientConfig::with_platform_verifier().map_err(|e| Error::Custom(e.to_string()))?;
        let host_client = HostClient::new(rustls_config)?;

        self.uploader
            .get_or_init(|| async {
                Arc::new(Uploader::new(
                    self.app_client.clone(),
                    host_client.clone(),
                    self.app_key.clone(),
                ))
            })
            .await;

        self.downloader
            .get_or_init(|| async {
                Arc::new(Downloader::new(
                    self.app_client.clone(),
                    host_client.clone(),
                    self.app_key.clone(),
                ))
            })
            .await;

        Ok(connected)
    }

    /// Requests permission for the app to connect to the indexer.
    ///
    /// # Returns
    /// A URL the user should visit to authorize the app.
    pub async fn request_app_connection(
        &self,
        meta: AppMeta,
    ) -> Result<RequestAuthResponse, Error> {
        let resp = self
            .app_client
            .request_app_connection(&RegisterAppRequest {
                name: meta.name,
                description: meta.description,
                service_url: meta
                    .service_url
                    .parse()
                    .map_err(|_| Error::Custom("invalid service URL".into()))?,
                logo_url: meta
                    .logo_url
                    .map(|u| u.parse())
                    .transpose()
                    .map_err(|_| Error::Custom("invalid logo URL".into()))?,
                callback_url: meta
                    .callback_url
                    .map(|u| u.parse())
                    .transpose()
                    .map_err(|_| Error::Custom("invalid callback URL".into()))?,
            })
            .await?;

        Ok(RequestAuthResponse {
            response_url: resp.response_url,
            status_url: resp.status_url,
        })
    }

    /// Waits for the user to authorize or reject the app.
    ///
    /// # Returns
    /// True if the app was authorized, false if it was rejected.
    pub async fn wait_for_connect(&self, resp: &RequestAuthResponse) -> Result<bool, Error> {
        let status_url: Url = resp
            .status_url
            .parse()
            .map_err(|_| Error::Custom("invalid status URL".into()))?;

        for _ in 0..100 {
            // wait up to 5 minutes
            if self
                .app_client
                .check_request_status(status_url.clone())
                .await?
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            debug!("waiting for user to authorize app");
        }
        let resp = self.app_client.check_app_authenticated().await?;
        Ok(resp)
    }

    /// Uploads data to the Sia network and pins it to the indexer
    ///
    /// # Warnings
    /// * The `encryption_key` must be unique for every upload. Reusing an
    ///   encryption key will compromise the security of the data.
    ///
    /// # Returns
    /// An object representing the uploaded data.
    pub async fn upload(
        &self,
        metadata: Option<Vec<u8>>,
        options: UploadOptions,
    ) -> Result<Upload, UploadError> {
        let uploader = match self.uploader.get() {
            Some(uploader) => uploader.clone(),
            None => return Err(UploadError::NotConnected),
        };
        let buf = ChunkedWriter::default();
        let (tx, rx) = oneshot::channel();
        let inner_buf = buf.clone();

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

        let result = tokio::spawn(async move {
            let res = uploader
                .upload(
                    inner_buf,
                    metadata,
                    quic::UploadOptions {
                        max_inflight: options.max_inflight as usize,
                        data_shards: options.data_shards,
                        parity_shards: options.parity_shards,
                        shard_uploaded: progress_tx,
                    },
                )
                .await
                .map_err(|e| e.into());
            let _ = tx.send(res);
        });
        Ok(Upload {
            reader: buf.clone(),
            result,
            rx: Mutex::new(Some(rx)),
        })
    }

    /// Initiates a download of the data referenced by the object, starting at `offset` and reading `length` bytes.
    ///
    /// # Returns
    /// A [`Download`] object that can be used to read the data in chunks
    pub async fn download(
        &self,
        encryption_key: Vec<u8>,
        object: &PinnedObject,
        options: DownloadOptions,
    ) -> Result<Download, DownloadError> {
        let downloader = match self.downloader.get() {
            Some(downloader) => downloader.clone(),
            None => return Err(DownloadError::NotConnected),
        };
        let slabs = object
            .slabs
            .iter()
            .map(|s| {
                Ok(SlabSlice {
                    slab_id: Hash256::from_str(s.id.as_str())?,
                    offset: s.offset as usize,
                    length: s.length as usize,
                })
            })
            .collect::<Result<Vec<SlabSlice>, HexParseError>>()?;
        let encryption_key = EncryptionKey::try_from(encryption_key.as_ref())
            .map_err(|err| DownloadError::Custom(err.to_string()))?;
        let slabs = SlabFetcher::new(self.app_client.clone(), slabs.clone());
        Ok(Download {
            encryption_key,
            slabs,
            state: Arc::new(Mutex::new(DownloadState {
                offset: options.offset,
                length: options.length.unwrap_or(object.size()),
                max_inflight: options.max_inflight,
            })),
            downloader,
        })
    }

    /// Initiates a download of all data in the shared object.
    ///
    /// # Returns
    /// A [`DownloadShared`] object that can be used to read the data in chunks
    pub async fn download_shared(
        &self,
        share_url: &str,
        options: DownloadOptions,
    ) -> Result<DownloadShared, DownloadError> {
        let downloader = match self.downloader.get() {
            Some(downloader) => downloader.clone(),
            None => return Err(DownloadError::NotConnected),
        };
        let share_url: Url = share_url
            .parse()
            .map_err(|e| DownloadError::Custom(format!("{e}")))?;
        let (object, encryption_key) = self.app_client.shared_object(share_url).await?;
        Ok(DownloadShared {
            encryption_key: EncryptionKey::from(encryption_key),
            slabs: object
                .slabs
                .iter()
                .map(|s| indexd::Slab {
                    encryption_key: s.encryption_key.clone(),
                    min_shards: s.min_shards,
                    offset: s.offset,
                    length: s.length,
                    sectors: s.sectors.clone(),
                })
                .collect(),
            state: Arc::new(Mutex::new(DownloadState {
                offset: options.offset,
                length: options.length.unwrap_or(object.size()),
                max_inflight: options.max_inflight,
            })),
            downloader,
        })
    }

    /// Fetches the metadata for a shared object via a share URL.
    pub async fn shared_object(&self, share_url: &str) -> Result<SharedObject, DownloadError> {
        let share_url: Url = share_url
            .parse()
            .map_err(|e| DownloadError::Custom(format!("{e}")))?;
        let (object, encryption_key) = self.app_client.shared_object(share_url).await?;

        Ok(SharedObject {
            key: object.key,
            slabs: object
                .slabs
                .into_iter()
                .map(|s| SharedSlab {
                    slab_id: s.id.to_string(),
                    encryption_key: s.encryption_key.as_ref().to_vec(),
                    min_shards: s.min_shards,
                    offset: s.offset as u32,
                    length: s.length as u32,
                    sectors: s
                        .sectors
                        .into_iter()
                        .map(|sec| PinnedSector {
                            root: sec.root.to_string(),
                            host_key: sec.host_key.to_string(),
                        })
                        .collect(),
                })
                .collect(),
            meta: object.meta,
            encryption_key: encryption_key.to_vec(),
        })
    }

    /// Returns a list of all usable hosts.
    pub async fn hosts(&self) -> Result<Vec<Host>, Error> {
        let hosts = self.app_client.hosts().await?;
        Ok(hosts.into_iter().map(|h| h.into()).collect())
    }

    /// Returns objects stored in the indexer. When syncing, the caller should
    /// provide the last `updated_at` timestamp and `key` seen in the `cursor
    /// parameter to avoid missing or duplicating objects.
    ///
    /// # Arguments
    /// * `cursor` can be used to paginate through the results. If `cursor` is `None`, the first page of results will be returned.
    /// * `limit` specifies the maximum number of objects to return.
    pub async fn objects(
        &self,
        cursor: Option<ObjectsCursor>,
        limit: u32,
    ) -> Result<Vec<PinnedObject>, Error> {
        let cursor = match cursor {
            Some(c) => Some(indexd::app_client::ObjectsCursor {
                after: c.after.into(),
                key: Hash256::from_str(c.key.as_str())?,
            }),
            None => None,
        };
        let objects = self
            .app_client
            .objects(cursor, Some(limit as usize))
            .await?;

        Ok(objects.into_iter().map(|o| o.into()).collect())
    }

    /// Saves an object to the indexer.
    pub async fn save_object(&self, object: PinnedObject) -> Result<(), Error> {
        let object = object.try_into()?;
        self.app_client.save_object(&object).await?;
        Ok(())
    }

    /// Deletes an object from the indexer.
    pub async fn delete_object(&self, key: String) -> Result<(), Error> {
        let key = Hash256::from_str(key.as_str())?;
        self.app_client.delete_object(&key).await?;
        Ok(())
    }

    /// Returns metadata about a specific object stored in the indexer.
    pub async fn object(&self, key: String) -> Result<PinnedObject, Error> {
        let key = Hash256::from_str(key.as_str())?;
        let obj = self.app_client.object(&key).await?;
        Ok(obj.into())
    }

    /// Returns metadata about a slab stored in the indexer.
    pub async fn slab(&self, slab_id: String) -> Result<PinnedSlab, Error> {
        let slab_id = Hash256::from_str(slab_id.as_str())?;
        let slab = self.app_client.slab(&slab_id).await?;
        Ok(slab.into())
    }

    /// Pins slabs to the indexer.
    pub async fn pin_slabs(&self, slabs: Vec<SlabPinParams>) -> Result<Vec<String>, Error> {
        let slabs: Vec<AppSlabPinParams> = slabs
            .into_iter()
            .map(|s| s.try_into())
            .collect::<Result<Vec<_>, _>>()?;
        let slab_ids = self.app_client.pin_slabs(slabs).await?;
        Ok(slab_ids.into_iter().map(|s| s.to_string()).collect())
    }

    /// Pins a slab to the indexer.
    pub async fn pin_slab(&self, slab: SlabPinParams) -> Result<String, Error> {
        let slab_id = self.app_client.pin_slab(slab.try_into()?).await?;
        Ok(slab_id.to_string())
    }

    /// UnpinSlab unpins a slab from the indexer.
    pub async fn unpin_slab(&self, slab_id: String) -> Result<(), Error> {
        let slab_id = Hash256::from_str(slab_id.as_str())?;
        self.app_client.unpin_slab(&slab_id).await?;
        Ok(())
    }

    /// Returns the current account.
    pub async fn account(&self) -> Result<Account, Error> {
        let account = self.app_client.account().await?;
        Ok(account.into())
    }

    /// Creates a signed URL that can be used to share object metadata
    /// with other people using an indexer.
    pub fn object_share_url(
        &self,
        object_key: String,
        encryption_key: Vec<u8>,
        valid_until: SystemTime,
    ) -> Result<String, Error> {
        let object_key = Hash256::from_str(&object_key)?;
        let encryption_key: [u8; 32] = encryption_key
            .try_into()
            .map_err(|_| Error::Custom("encryption key must be 32 bytes".into()))?;
        let u =
            self.app_client
                .object_share_url(&object_key, encryption_key, valid_until.into())?;
        Ok(u.to_string())
    }
}

pub type UploadReceiver = Mutex<Option<oneshot::Receiver<Result<indexd::UploadMeta, UploadError>>>>;

/// Uploads data to the Sia network. It does so in chunks to support large files in
/// arbitrary languages.
///
/// Language bindings should provide a higher-level implementation that wraps a stream.
#[derive(uniffi::Object)]
pub struct Upload {
    reader: ChunkedWriter,
    result: JoinHandle<()>,
    rx: UploadReceiver,
}

#[uniffi::export(async_runtime = "tokio")]
impl Upload {
    /// Writes a chunk of data to the Sia network. The data will be
    /// erasure-coded and encrypted before upload.
    ///
    /// Chunks should be written until EoF, then call [`Upload::finalize`].
    pub async fn write(&self, buf: &[u8]) -> Result<(), UploadError> {
        if self.result.is_finished() {
            return Err(UploadError::Closed);
        }
        self.reader.push_chunk(buf.to_vec()).await?;
        Ok(())
    }

    /// Waits for all chunks of data to be pinned to the indexer and
    /// returns the metadata. Data can no longer be written after
    /// calling finalize.
    ///
    /// The caller must store the metadata locally in order to download
    /// it in the future.
    pub async fn finalize(&self) -> Result<UploadMeta, UploadError> {
        self.reader.close()?;
        let rx = self
            .rx
            .lock()
            .map_err(|e| UploadError::Custom(e.to_string()))?
            .take()
            .ok_or(UploadError::Closed)?;
        let object = rx.await.map_err(|e| UploadError::Custom(e.to_string()))??;
        Ok(object.into())
    }
}

#[derive(Clone, uniffi::Object)]
struct DownloadState {
    offset: u64,
    length: u64,
    max_inflight: u8,
}

/// Downloads data from the Sia network. It does so in chunks to support large files in
/// arbitrary languages.
///
/// Language bindings should provide a higher-level implementation that wraps a stream.
#[derive(uniffi::Object)]
pub struct Download {
    encryption_key: EncryptionKey,
    slabs: SlabFetcher,
    state: Arc<Mutex<DownloadState>>,
    downloader: Arc<Downloader>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Download {
    fn rem(&self) -> u64 {
        let state = self.state.lock().unwrap();
        state.length.saturating_sub(state.offset)
    }

    fn update(&self, n: u64) {
        let mut state = self.state.lock().unwrap();
        state.offset += n;
    }

    fn params(&self) -> DownloadState {
        self.state.lock().unwrap().clone()
    }

    /// Reads a chunk of data from the Sia network.
    ///
    /// # Returns
    /// A vector containing the chunk of data read. If the vector is empty, the end of the download has been reached.
    pub async fn read_chunk(&self) -> Result<Vec<u8>, DownloadError> {
        const DOWNLOAD_CHUNK_SIZE: u64 = 1 << 19; // 512 KiB

        let state = self.params();
        let rem = state
            .length
            .saturating_sub(state.offset)
            .min(DOWNLOAD_CHUNK_SIZE);
        if rem == 0 {
            return Ok(Vec::with_capacity(0));
        }
        let mut buf = Vec::with_capacity(rem as usize);
        self.downloader
            .download(
                &mut buf,
                self.encryption_key.clone(),
                self.slabs.clone(),
                quic::DownloadOptions {
                    offset: state.offset as usize,
                    length: Some(rem as usize),
                    max_inflight: state.max_inflight as usize,
                },
            )
            .await?;
        self.update(buf.len() as u64);
        Ok(buf)
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

/// Downloads data from the Sia network. It does so in chunks to support large files in
/// arbitrary languages.
///
/// Language bindings should provide a higher-level implementation that wraps a stream.
#[derive(uniffi::Object)]
pub struct DownloadShared {
    encryption_key: EncryptionKey,
    slabs: VecDeque<indexd::Slab>,
    state: Arc<Mutex<DownloadState>>,
    downloader: Arc<Downloader>,
}

#[uniffi::export(async_runtime = "tokio")]
impl DownloadShared {
    fn rem(&self) -> u64 {
        let state = self.state.lock().unwrap();
        state.length.saturating_sub(state.offset)
    }

    fn update(&self, n: u64) {
        let mut state = self.state.lock().unwrap();
        state.offset += n;
    }

    fn params(&self) -> DownloadState {
        self.state.lock().unwrap().clone()
    }

    /// Reads a chunk of data from the Sia network.
    ///
    /// # Returns
    /// A vector containing the chunk of data read. If the vector is empty, the end of the download has been reached.
    pub async fn read_chunk(&self) -> Result<Vec<u8>, DownloadError> {
        const DOWNLOAD_CHUNK_SIZE: u64 = 1 << 19; // 512 KiB

        let state = self.params();
        let rem = state
            .length
            .saturating_sub(state.offset)
            .min(DOWNLOAD_CHUNK_SIZE);
        if rem == 0 {
            return Ok(Vec::with_capacity(0));
        }
        let mut buf = Vec::with_capacity(rem as usize);
        self.downloader
            .download(
                &mut buf,
                self.encryption_key.clone(),
                self.slabs.clone(),
                quic::DownloadOptions {
                    offset: state.offset as usize,
                    length: Some(rem as usize),
                    ..Default::default()
                },
            )
            .await?;
        self.update(buf.len() as u64);
        Ok(buf)
    }
}
