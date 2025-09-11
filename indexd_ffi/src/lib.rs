uniffi::setup_scaffolding!();

use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use indexd::app_client::{
    Client as AppClient, RegisterAppRequest, SlabPinParams as AppSlabPinParams,
};
use indexd::quic::{Client as HostClient, Downloader, Uploader};
use indexd::{SlabSlice, Url};
use log::debug;
use rustls::{ClientConfig, RootCertStore};
use sia::encryption::EncryptionKey;
use sia::rhp::SECTOR_SIZE;
use sia::signing::{PrivateKey, PublicKey};
use sia::types::{self, Hash256, HexParseError};
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::{OnceCell, oneshot};
use tokio::task::JoinHandle;

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
    pub metadata: Vec<u8>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

impl From<indexd::Object> for PinnedObject {
    fn from(o: indexd::Object) -> Self {
        Self {
            key: o.key.to_string(),
            slabs: o.slabs.into_iter().map(|s| s.into()).collect(),
            metadata: o.meta,
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
            meta: Vec::with_capacity(0), // TODO: handle encryption
            created_at: self.created_at.into(),
            updated_at: self.updated_at.into(),
        })
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

impl From<indexd::app_client::Slab> for PinnedSlab {
    fn from(s: indexd::app_client::Slab) -> Self {
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
        let mut roots = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            // Ignore any certs that fail to parse
            let _ = roots.add(cert);
        }

        let client_crypto = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let host_client = HostClient::new(client_crypto)?;

        self.uploader
            .get_or_init(|| async {
                Arc::new(Uploader::new(
                    self.app_client.clone(),
                    host_client.clone(),
                    self.app_key.clone(),
                    12,
                ))
            })
            .await;

        self.downloader
            .get_or_init(|| async {
                Arc::new(Downloader::new(
                    self.app_client.clone(),
                    host_client.clone(),
                    self.app_key.clone(),
                    12,
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

    pub async fn upload(
        &self,
        encryption_key: Vec<u8>,
        data_shards: u8,
        parity_shards: u8,
        metadata: Option<Vec<u8>>,
    ) -> Result<Upload, UploadError> {
        let uploader = match self.uploader.get() {
            Some(uploader) => uploader.clone(),
            None => return Err(UploadError::NotConnected),
        };
        let buf = ChunkedWriter::default();
        let (tx, rx) = oneshot::channel();
        let inner_buf = buf.clone();
        let encryption_key = EncryptionKey::try_from(encryption_key.as_ref())
            .map_err(|err| UploadError::Custom(err.to_string()))?;
        let result = tokio::spawn(async move {
            let res = uploader
                .upload(
                    inner_buf,
                    encryption_key,
                    data_shards,
                    parity_shards,
                    metadata,
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

    /// Initiates a download of all the data specified in the slabs.
    pub async fn download(
        &self,
        object: &PinnedObject,
        encryption_key: Vec<u8>,
    ) -> Result<Download, DownloadError> {
        let length = object.slabs.iter().fold(0_u64, |v, s| v + s.length as u64);
        self.download_range(encryption_key, object, 0, length).await
    }

    /// Initiates a download of the data specified in the slabs.
    pub async fn download_range(
        &self,
        encryption_key: Vec<u8>,
        object: &PinnedObject,
        offset: u64,
        length: u64,
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
        Ok(Download {
            encryption_key,
            slabs,
            state: Arc::new(Mutex::new(DownloadState { offset, length })),
            downloader,
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
    /// `cursor` can be used to paginate through the results.
    /// If `cursor` is `None`, the first page of results will be returned.
    ///
    /// `limit` specifies the maximum number of objects to return.
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

    /// Pins a slab to the indexer.
    pub async fn pin_slab(&self, slab_pin_params: SlabPinParams) -> Result<String, Error> {
        let slab_id = self
            .app_client
            .pin_slab(slab_pin_params.try_into()?)
            .await?;
        Ok(slab_id.to_string())
    }

    /// UnpinSlab unpins a slab from the indexer.
    pub async fn unpin_slab(&self, slab_id: String) -> Result<(), Error> {
        let slab_id = Hash256::from_str(slab_id.as_str())?;
        self.app_client.unpin_slab(&slab_id).await?;
        Ok(())
    }

    pub async fn shared_object(&self, share_url: String) -> Result<PinnedObject, Error> {
        let share_url: Url = share_url
            .parse()
            .map_err(|e| Error::Custom(format!("{e}")))?;
        let (object, _) = self.app_client.shared_object(share_url).await?;
        Ok(object.into())
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

pub type UploadReceiver = Mutex<Option<oneshot::Receiver<Result<indexd::Object, UploadError>>>>;

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
    /// Chunks should be written until EoF, then call [`finalize`].
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
    pub async fn finalize(&self) -> Result<PinnedObject, UploadError> {
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
}

/// Downloads data from the Sia network. It does so in chunks to support large files in
/// arbitrary languages.
///
/// Language bindings should provide a higher-level implementation that wraps a stream.
#[derive(uniffi::Object)]
pub struct Download {
    encryption_key: EncryptionKey,
    slabs: Vec<SlabSlice>,
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
            .download_range(
                &mut buf,
                self.encryption_key.clone(),
                &self.slabs,
                state.offset as usize,
                rem as usize,
            )
            .await?;
        self.update(buf.len() as u64);
        Ok(buf)
    }
}
