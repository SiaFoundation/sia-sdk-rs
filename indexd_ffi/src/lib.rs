uniffi::setup_scaffolding!();

use base64::prelude::*;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::SystemTime;
use tokio::runtime::{self, Runtime};
use tokio_util::task::AbortOnDropHandle;

use indexd::{SealedObjectError, Url};
use sia::rhp::SECTOR_SIZE;
use sia::signing::{PublicKey, Signature};
use sia::types::{self, Hash256, HexParseError};
use sia::{encoding, encryption};
use thiserror::Error;
use tokio::sync::mpsc;

mod tls;

mod logging;
pub use logging::*;

mod builder;
pub use builder::*;

mod io;
pub use io::*;

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

    #[error("hex error: {0}")]
    HexParseError(#[from] sia::types::HexParseError),

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

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Upload(#[from] indexd::UploadError),

    #[error("task error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("custom error: {0}")]
    Custom(String),
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum DownloadError {
    #[error("{0}")]
    Download(#[from] indexd::DownloadError),

    #[error("task error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
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
            encrypted_data_key: sealed.encrypted_data_key,
            encrypted_metadata_key: sealed.encrypted_metadata_key,
            slabs: sealed
                .slabs
                .into_iter()
                .map(|s| s.try_into().unwrap())
                .collect(),
            encrypted_metadata: sealed.encrypted_metadata,
            data_signature: Signature::try_from(sealed.data_signature.as_ref())?,
            metadata_signature: Signature::try_from(sealed.metadata_signature.as_ref())?,
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
        inner.size()
    }

    /// Returns the slabs that make up the object.
    pub fn slabs(&self) -> Vec<Slab> {
        let inner = self.inner.lock().unwrap();
        inner.slabs().iter().cloned().map(|s| s.into()).collect()
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
        (*inner.created_at()).into()
    }

    /// Returns the time the object was last updated.
    pub fn updated_at(&self) -> SystemTime {
        let inner = self.inner.lock().unwrap();
        (*inner.updated_at()).into()
    }
}

/// A sealed object represents an object that has been encrypted
/// for secure offline storage or processing. It can be opened using
/// an app key to retrieve the original object.
#[derive(uniffi::Record)]
pub struct SealedObject {
    pub id: String,
    pub encrypted_data_key: Vec<u8>,
    pub encrypted_metadata_key: Vec<u8>,
    pub slabs: Vec<Slab>,
    pub encrypted_metadata: Vec<u8>,
    pub data_signature: Vec<u8>,
    pub metadata_signature: Vec<u8>,

    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

impl From<indexd::SealedObject> for SealedObject {
    fn from(o: indexd::SealedObject) -> Self {
        Self {
            id: o.id().to_string(),
            encrypted_data_key: o.encrypted_data_key,
            encrypted_metadata_key: o.encrypted_metadata_key,
            slabs: o.slabs.into_iter().map(|s| s.into()).collect(),
            encrypted_metadata: o.encrypted_metadata,
            data_signature: o.data_signature.as_ref().to_vec(),
            metadata_signature: o.metadata_signature.as_ref().to_vec(),
            created_at: o.created_at.into(),
            updated_at: o.updated_at.into(),
        }
    }
}

impl TryInto<indexd::SealedObject> for SealedObject {
    type Error = SealedObjectError;

    fn try_into(self) -> Result<indexd::SealedObject, Self::Error> {
        let sealed = indexd::SealedObject {
            encrypted_data_key: self.encrypted_data_key,
            encrypted_metadata_key: self.encrypted_metadata_key,
            slabs: self
                .slabs
                .into_iter()
                .map(|s| s.try_into().unwrap())
                .collect(),
            encrypted_metadata: self.encrypted_metadata,
            data_signature: Signature::try_from(self.data_signature.as_ref())?,
            metadata_signature: Signature::try_from(self.metadata_signature.as_ref())?,
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
    pub id: String,
    pub deleted: bool,
    pub updated_at: SystemTime,
    pub object: Option<Arc<PinnedObject>>,
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
    pub good_for_upload: bool,
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
            good_for_upload: h.good_for_upload,
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
            good_for_upload: self.good_for_upload,
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

#[derive(uniffi::Record)]
pub struct App {
    pub id: String,
    pub description: String,
    pub service_url: Option<String>,
    pub logo_url: Option<String>,
}

/// An account registered on the indexer.
#[derive(uniffi::Record)]
pub struct Account {
    pub account_key: String,
    pub max_pinned_data: u64,
    pub pinned_data: u64,
    pub app: App,
    pub last_used: SystemTime,
}

impl From<indexd::app_client::Account> for Account {
    fn from(a: indexd::app_client::Account) -> Self {
        Self {
            account_key: a.account_key.to_string(),
            max_pinned_data: a.max_pinned_data,
            pinned_data: a.pinned_data,
            app: App {
                id: a.app.id.to_string(),
                description: a.app.description,
                service_url: a.app.service_url,
                logo_url: a.app.logo_url,
            },
            last_used: a.last_used.into(),
        }
    }
}

/// A packed upload allows multiple objects to be uploaded together in a single upload. This can be more
/// efficient than uploading each object separately if the size of the object is less than the minimum
/// slab size.
#[derive(uniffi::Object)]
pub struct PackedUpload {
    packed_upload: Arc<tokio::sync::Mutex<Option<indexd::PackedUpload>>>,
}

#[uniffi::export]
impl PackedUpload {
    /// Returns the number of bytes remaining until reaching the optimal
    /// packed size. Adding objects larger than this will start a new slab.
    /// To minimize padding, prioritize objects that fit within the remaining
    /// size.
    pub async fn remaining(&self) -> Result<u64, UploadError> {
        let packed_upload = self.packed_upload.clone();
        spawn(async move {
            let mut guard = packed_upload.lock().await;
            let packed_upload = guard.as_mut().ok_or(UploadError::Closed)?;
            Ok(packed_upload.remaining())
        })
        .await?
    }

    /// Adds a new object to the upload. The data will be read until EOF and packed into
    /// the upload. The resulting object will contain the metadata needed to download the object. The caller
    /// must call [finalize](Self::finalize) to get the resulting objects after all objects have been added.
    pub async fn add(&self, reader: Arc<dyn Reader>) -> Result<u64, UploadError> {
        let packed_upload = self.packed_upload.clone();
        spawn(async move {
            let mut guard = packed_upload.lock().await;
            let packed_upload = guard.as_mut().ok_or(UploadError::Closed)?;
            let size = packed_upload.add(adapt_ffi_reader(reader)).await?;
            Ok(size)
        })
        .await?
    }

    /// Finalizes the upload and returns the resulting objects. This will wait for all readers
    /// to finish and all slabs to be uploaded before returning. The resulting objects will contain the metadata needed to download the objects.
    ///
    /// The caller must pin the resulting objects to the indexer when ready.
    pub async fn finalize(&self) -> Result<Vec<Arc<PinnedObject>>, UploadError> {
        let packed_upload = self.packed_upload.clone();
        spawn(async move {
            let mut guard = packed_upload.lock().await;
            let packed_upload = guard.take().ok_or(UploadError::Closed)?;
            let objects = packed_upload.finalize().await?;
            Ok(objects
                .into_iter()
                .map(|o| {
                    Arc::new(PinnedObject {
                        inner: Arc::new(Mutex::new(o)),
                    })
                })
                .collect())
        })
        .await?
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

    /// Creates a new packed upload. This allows multiple objects to be packed together
    /// for more efficient uploads. The returned `PackedUpload` can be used to add objects to the upload, and then finalized to get the resulting objects.
    ///
    /// # Arguments
    /// * `options` - The [UploadOptions] to use for the upload.
    ///
    /// # Returns
    /// A [PackedUpload] that can be used to add objects and finalize the upload.
    pub async fn upload_packed(&self, options: UploadOptions) -> PackedUpload {
        let sdk = self.inner.clone();
        spawn(async move {
            // this needs to be in a spawn to ensure a tokio runtime is available since `upload_packed` spawns a task
            PackedUpload {
                packed_upload: Arc::new(tokio::sync::Mutex::new(Some(sdk.upload_packed(
                    indexd::UploadOptions {
                        max_inflight: options.max_inflight as usize,
                        data_shards: options.data_shards,
                        parity_shards: options.parity_shards,
                        shard_uploaded: None,
                    },
                )))),
            }
        })
        .await
        .unwrap()
    }

    /// Uploads data to the Sia network and pins it to the indexer
    ///
    /// # Arguments
    /// * `options` - The [UploadOptions] to use for the upload
    ///
    /// # Returns
    /// An object representing the uploaded data.
    pub async fn upload(
        &self,
        r: Arc<dyn Reader>,
        options: UploadOptions,
    ) -> Result<PinnedObject, UploadError> {
        let sdk = self.inner.clone();
        spawn(async move {
            let r = adapt_ffi_reader(r);
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
            let obj = sdk
                .upload(
                    r,
                    indexd::UploadOptions {
                        max_inflight: options.max_inflight as usize,
                        data_shards: options.data_shards,
                        parity_shards: options.parity_shards,
                        shard_uploaded: progress_tx,
                    },
                )
                .await?;
            Ok(PinnedObject {
                inner: Arc::new(Mutex::new(obj)),
            })
        })
        .await?
    }

    /// Initiates a download of the data referenced by the object, starting at `offset` and reading `length` bytes.
    pub async fn download(
        &self,
        w: Arc<dyn Writer>,
        object: Arc<PinnedObject>,
        options: DownloadOptions,
    ) -> Result<(), DownloadError> {
        const CHUNK_SIZE: usize = 1 << 19; // 512KiB
        let object = object.object();
        let object_size = object.size();
        let offset = options.offset;
        let max_length = options.length.unwrap_or(object_size);
        let max_inflight = options.max_inflight;
        let sdk = self.inner.clone();
        spawn(async move {
            let w = adapt_ffi_writer(w.clone());
            for offset in (offset..max_length).step_by(CHUNK_SIZE) {
                sdk.download(
                    w.clone(),
                    &object,
                    indexd::DownloadOptions {
                        offset,
                        length: Some(max_length.min(CHUNK_SIZE as u64)),
                        max_inflight: max_inflight as usize,
                    },
                )
                .await?;
            }
            Ok(())
        })
        .await?
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
                        id: event.id.to_string(),
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

    /// Updates the metadata of an object stored in the indexer. The object must already be pinned to
    /// the indexer.
    pub async fn update_object_metadata(&self, object: Arc<PinnedObject>) -> Result<(), Error> {
        let object = object.object();
        let sdk = self.inner.clone();
        spawn(async move {
            sdk.update_object_metadata(&object).await?;
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
    pub async fn shared_object(&self, shared_url: &str) -> Result<PinnedObject, Error> {
        let shared_url: Url = shared_url
            .parse()
            .map_err(|e| Error::Custom(format!("{e}")))?;
        let sdk = self.inner.clone();
        spawn(async move {
            let object = sdk.shared_object(shared_url).await?;
            Ok(PinnedObject {
                inner: Arc::new(Mutex::new(object)),
            })
        })
        .await?
    }

    /// Pins an object to the indexer
    pub async fn pin_object(&self, object: Arc<PinnedObject>) -> Result<(), Error> {
        let sdk = self.inner.clone();
        spawn(async move {
            sdk.pin_object(&object.object()).await?;
            Ok(())
        })
        .await?
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
