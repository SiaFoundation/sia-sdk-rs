uniffi::setup_scaffolding!();

use base64::prelude::*;
use rand::TryRngCore;
use rand::rngs::OsRng;
use sia::blake2::{Blake2b256, Digest};
use sia::seed::{Seed, SeedError};
use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio_util::sync::CancellationToken;

use indexd::app_client::{Client as AppClient, RegisterAppRequest, SlabPinParams};
use indexd::quic::{Client as HostClient, Downloader, SlabFetcher, Uploader};
use indexd::{Object, SealedObjectError, SlabSlice, Url, quic};
use log::debug;
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use sia::rhp::SECTOR_SIZE;
use sia::signing::{self, PrivateKey, PublicKey, Signature};
use sia::types::{self, Hash256, HexParseError};
use sia::{encoding, encryption};
use thiserror::Error;
use tokio::io::AsyncRead;
use tokio::sync::OnceCell;
use tokio::sync::mpsc::{self, Receiver, Sender};
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

    #[error("sealed object error: {0}")]
    SealedObject(#[from] SealedObjectError),

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
pub enum AppKeyError {
    #[error("seed error: {0}")]
    RecoveryPhrase(#[from] SeedError),

    #[error("invalid app ID length: {0}, expected 32 bytes")]
    AppIdLength(usize),
}

/// An AppKey is used to sign requests to the indexer.
#[derive(uniffi::Object)]
pub struct AppKey(signing::PrivateKey);

/// Generates a new BIP-32 12-word recovery phrase.
#[uniffi::export]
pub fn generate_recovery_phrase() -> String {
    let mut seed = [0u8; 16];
    OsRng.try_fill_bytes(&mut seed).unwrap();
    let seed = Seed::new(seed);
    seed.to_mnemonic()
}

#[uniffi::export]
impl AppKey {
    /// Creates a new AppKey from a recovery phrase and a unique app ID.
    /// The app ID should be a unique 32-byte value. The value is not secret,
    /// but it should be random and unique to the app.
    #[uniffi::constructor]
    pub fn new(recovery_phrase: String, app_id: Vec<u8>) -> Result<Self, AppKeyError> {
        if app_id.len() != 32 {
            return Err(AppKeyError::AppIdLength(app_id.len()));
        }
        let seed = Seed::from_mnemonic(&recovery_phrase)?;
        let mut state = Blake2b256::new();
        state.update(seed.as_bytes());
        state.update(app_id);

        let seed = state.finalize().into();
        Ok(Self(PrivateKey::from_seed(&seed)))
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
            encrypted_metadata: sealed.encrypted_metadata,
            signature: Signature::try_from(sealed.signature.as_ref())?,
            created_at: sealed.created_at.into(),
            updated_at: sealed.updated_at.into(),
        };
        let obj = sealed.open(&app_key.0)?;
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
        SealedObject::from(inner.seal(&app_key.0))
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
            encrypted_metadata: o.encrypted_metadata,
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
            encrypted_metadata: self.encrypted_metadata,
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
    pub id: String,
    pub offset: u32,
    pub length: u32,
}

impl From<SlabSlice> for Slab {
    fn from(s: SlabSlice) -> Self {
        Self {
            id: s.slab_id.to_string(),
            offset: s.offset,
            length: s.length,
        }
    }
}

impl TryInto<SlabSlice> for Slab {
    type Error = HexParseError;

    fn try_into(self) -> Result<SlabSlice, Self::Error> {
        Ok(SlabSlice {
            slab_id: Hash256::from_str(self.id.as_str())?,
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
    pub fn new(indexer_url: String, app_key: Arc<AppKey>) -> Result<Self, Error> {
        let app_client = AppClient::new(indexer_url, app_key.0.clone())?;

        Ok(Self {
            app_key: app_key.0.clone(),
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
    pub async fn upload(&self, options: UploadOptions) -> Result<Upload, UploadError> {
        let uploader = match self.uploader.get() {
            Some(uploader) => uploader.clone(),
            None => return Err(UploadError::NotConnected),
        };
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
            uploader
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
                .await
                .map_err(|e| e.into())
        });
        Ok(Upload {
            reader: buf.clone(),
            result: Mutex::new(Some(result)),
            cancel: cancel_token,
        })
    }

    /// Initiates a download of the data referenced by the object, starting at `offset` and reading `length` bytes.
    ///
    /// # Returns
    /// A [Download] object that can be used to read the data in chunks
    pub fn download(
        &self,
        object: Arc<PinnedObject>,
        options: DownloadOptions,
    ) -> Result<Download, DownloadError> {
        let downloader = match self.downloader.get() {
            Some(downloader) => downloader.clone(),
            None => return Err(DownloadError::NotConnected),
        };
        let object = object.object();
        let object_size = object.size();
        let slabs = SlabFetcher::new(self.app_client.clone(), object.slabs.clone());
        Ok(Download {
            object,
            slabs,
            state: Arc::new(Mutex::new(DownloadState {
                offset: options.offset,
                length: options.length.unwrap_or(object_size),
                max_inflight: options.max_inflight,
            })),
            downloader,
        })
    }

    /// Initiates a download of all data in the shared object.
    ///
    /// # Returns
    /// A [`DownloadShared`] object that can be used to read the data in chunks
    pub fn download_shared(
        &self,
        shared_object: Arc<SharedObject>,
        options: DownloadOptions,
    ) -> Result<DownloadShared, DownloadError> {
        let downloader = match self.downloader.get() {
            Some(downloader) => downloader.clone(),
            None => return Err(DownloadError::NotConnected),
        };
        let object_size = shared_object.0.size();
        let slabs = shared_object.0.slabs().clone();
        let slab_iterator = VecDeque::from(slabs);
        Ok(DownloadShared {
            shared_object: shared_object.0.clone(),
            slabs: slab_iterator,
            state: Arc::new(Mutex::new(DownloadState {
                offset: options.offset,
                length: options.length.unwrap_or(object_size),
                max_inflight: options.max_inflight,
            })),
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
    /// * `cursor` can be used to paginate through the results. If `cursor` is `None`, the first page of results will be returned.
    /// * `limit` specifies the maximum number of objects to return.
    pub async fn objects(
        &self,
        cursor: Option<ObjectsCursor>,
        limit: u32,
    ) -> Result<Vec<Arc<PinnedObject>>, Error> {
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

        let objects = objects
            .into_iter()
            .filter_map(|event| {
                if event.deleted {
                    None
                } else {
                    event.object.map(|sealed| {
                        sealed.open(&self.app_key).map(|obj| {
                            Arc::new(PinnedObject {
                                inner: Arc::new(Mutex::new(obj)),
                            })
                        })
                    })
                }
            })
            .collect::<Result<Vec<Arc<PinnedObject>>, SealedObjectError>>()?;
        Ok(objects)
    }

    /// Saves an object to the indexer.
    pub async fn save_object(&self, object: Arc<PinnedObject>) -> Result<(), Error> {
        let object = object.object();
        self.app_client
            .save_object(&object.seal(&self.app_key))
            .await?;
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
        let obj = obj.open(&self.app_key)?;
        Ok(PinnedObject {
            inner: Arc::new(Mutex::new(obj)),
        })
    }

    /// Returns metadata about a slab stored in the indexer.
    pub async fn slab(&self, slab_id: String) -> Result<PinnedSlab, Error> {
        let slab_id = Hash256::from_str(slab_id.as_str())?;
        let slab = self.app_client.slab(&slab_id).await?;
        Ok(slab.into())
    }

    /// Unpins slabs not used by any object on the account.
    pub async fn prune_slabs(&self) -> Result<(), Error> {
        self.app_client.prune_slabs().await?;
        Ok(())
    }

    /// Returns the current account.
    pub async fn account(&self) -> Result<Account, Error> {
        let account = self.app_client.account().await?;
        Ok(account.into())
    }

    /// Creates a signed URL that can be used to share object metadata
    /// with other people using an indexer.
    pub fn share_object(
        &self,
        object: Arc<PinnedObject>,
        valid_until: SystemTime,
    ) -> Result<String, Error> {
        let u = self
            .app_client
            .object_share_url(&object.object(), valid_until.into())?;
        Ok(u.to_string())
    }

    /// Retrieves a shared object from a signed URL.
    pub async fn shared_object(&self, shared_url: &str) -> Result<SharedObject, Error> {
        let shared_object = self
            .app_client
            .shared_object(
                shared_url
                    .parse()
                    .map_err(|e| Error::Custom(format!("{e}")))?,
            )
            .await?;
        Ok(SharedObject(shared_object))
    }

    /// Pins a shared object to the indexer and returns a [PinnedObject].
    pub async fn pin_shared(&self, shared: Arc<SharedObject>) -> Result<PinnedObject, Error> {
        let shared_object = shared.0.clone();

        let slabs = shared_object
            .slabs()
            .iter()
            .map(|s| SlabPinParams {
                encryption_key: s.encryption_key.clone(),
                min_shards: s.min_shards,
                sectors: s.sectors.clone(),
            })
            .collect();

        self.app_client.pin_slabs(slabs).await?;

        let object: Object = shared_object.into();
        let sealed_object: indexd::SealedObject = object.seal(&self.app_key);
        self.app_client.save_object(&sealed_object).await?;
        Ok(PinnedObject {
            inner: Arc::new(Mutex::new(object)),
        })
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

#[uniffi::export(async_runtime = "tokio")]
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
                let object = result.await.unwrap()?;
                Ok(PinnedObject {
                    inner: Arc::new(Mutex::new(object)),
                })
            }
            None => Err(UploadError::Closed),
        }
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
    object: indexd::Object,
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
        let mut w = self.object.writer(&mut buf, state.offset as usize);
        self.downloader
            .download_slabs(
                &mut w,
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
    shared_object: indexd::SharedObject,
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
        let mut w = self.shared_object.writer(&mut buf, state.offset as usize);
        self.downloader
            .download_slabs(
                &mut w,
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
