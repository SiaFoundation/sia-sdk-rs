use chrono::{DateTime, Utc};
use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;
use sia_core::signing::{PublicKey, Signature};
use sia_core::types::{self, Hash256, HexParseError};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;

mod builder;
mod io;
mod logging;

pub use builder::*;
pub use io::SendableReader;
pub use logging::*;

/// Metadata about an application connecting to the indexer.
#[napi(object)]
pub struct AppMeta {
    pub id: Buffer,
    pub name: String,
    pub description: String,
    pub service_url: String,
    pub logo_url: Option<String>,
    pub callback_url: Option<String>,
}

/// The protocol used in a network address.
#[napi(string_enum)]
pub enum AddressProtocol {
    SiaMux,
    Quic,
}

/// A network address of a storage provider on the Sia network.
#[napi(object)]
pub struct NetAddress {
    pub protocol: AddressProtocol,
    pub address: String,
}

/// A sealed object for offline storage.
#[napi(object)]
pub struct SealedObject {
    pub id: String,
    pub encrypted_data_key: Buffer,
    pub encrypted_metadata_key: Buffer,
    pub slabs: Vec<Slab>,
    pub encrypted_metadata: Buffer,
    pub data_signature: Buffer,
    pub metadata_signature: Buffer,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<sia_storage::SealedObject> for SealedObject {
    fn from(o: sia_storage::SealedObject) -> Self {
        Self {
            id: o.id().to_string(),
            encrypted_data_key: Buffer::from(o.encrypted_data_key),
            encrypted_metadata_key: Buffer::from(o.encrypted_metadata_key),
            slabs: o.slabs.into_iter().map(|s| s.into()).collect(),
            encrypted_metadata: Buffer::from(o.encrypted_metadata),
            data_signature: Buffer::from(o.data_signature.as_ref().to_vec()),
            metadata_signature: Buffer::from(o.metadata_signature.as_ref().to_vec()),
            created_at: o.created_at,
            updated_at: o.updated_at,
        }
    }
}

impl TryInto<sia_storage::SealedObject> for SealedObject {
    type Error = napi::Error;

    fn try_into(self) -> Result<sia_storage::SealedObject> {
        let sealed = sia_storage::SealedObject {
            encrypted_data_key: self.encrypted_data_key.to_vec(),
            encrypted_metadata_key: self.encrypted_metadata_key.to_vec(),
            slabs: self
                .slabs
                .into_iter()
                .map(|s| s.try_into())
                .collect::<Result<Vec<sia_storage::Slab>>>()?,
            encrypted_metadata: self.encrypted_metadata.to_vec(),
            data_signature: Signature::try_from(self.data_signature.as_ref())
                .map_err(|e| Error::from_reason(e.to_string()))?,
            metadata_signature: Signature::try_from(self.metadata_signature.as_ref())
                .map_err(|e| Error::from_reason(e.to_string()))?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        };
        if sealed.id().to_string() != self.id {
            return Err(Error::from_reason("sealed object contents mismatch"));
        }
        Ok(sealed)
    }
}

/// An object event from the indexer.
#[napi]
pub struct ObjectEvent {
    id: String,
    deleted: bool,
    updated_at: DateTime<Utc>,
    object: Option<PinnedObject>,
}

#[napi]
impl ObjectEvent {
    #[napi(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    #[napi(getter)]
    pub fn deleted(&self) -> bool {
        self.deleted
    }

    #[napi(getter)]
    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    #[napi(getter)]
    pub fn object(&self) -> Option<PinnedObject> {
        self.object.as_ref().map(|o| PinnedObject {
            inner: Mutex::new(o.inner.lock().unwrap().clone()),
        })
    }
}

/// Information about a storage provider on the Sia network.
#[napi(object)]
pub struct Host {
    pub public_key: String,
    pub addresses: Vec<NetAddress>,
    pub country_code: String,
    pub latitude: f64,
    pub longitude: f64,
    pub good_for_upload: bool,
}

impl From<sia_storage::Host> for Host {
    fn from(h: sia_storage::Host) -> Self {
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

/// A sector stored on a specific host.
#[napi(object)]
#[derive(Clone)]
pub struct PinnedSector {
    pub root: String,
    pub host_key: String,
}

/// A pinned slab from the indexer.
#[napi(object)]
pub struct PinnedSlab {
    pub id: String,
    pub encryption_key: Buffer,
    pub min_shards: u8,
    pub sectors: Vec<PinnedSector>,
}

impl From<sia_storage::PinnedSlab> for PinnedSlab {
    fn from(s: sia_storage::PinnedSlab) -> Self {
        Self {
            id: s.id.to_string(),
            encryption_key: Buffer::from(s.encryption_key.as_ref().to_vec()),
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

/// A slab representing a contiguous erasure-coded segment of a file.
#[napi(object)]
pub struct Slab {
    pub encryption_key: Buffer,
    pub min_shards: u8,
    pub sectors: Vec<PinnedSector>,
    pub offset: u32,
    pub length: u32,
}

impl From<sia_storage::Slab> for Slab {
    fn from(s: sia_storage::Slab) -> Self {
        Self {
            encryption_key: Buffer::from(s.encryption_key.as_ref().to_vec()),
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

impl TryInto<sia_storage::Slab> for Slab {
    type Error = napi::Error;

    fn try_into(self) -> Result<sia_storage::Slab> {
        Ok(sia_storage::Slab {
            encryption_key: sia_storage::EncryptionKey::try_from(self.encryption_key.as_ref())
                .map_err(|e| Error::from_reason(e.to_string()))?,
            min_shards: self.min_shards,
            sectors: self
                .sectors
                .into_iter()
                .map(|sec| -> Result<sia_storage::Sector> {
                    Ok(sia_storage::Sector {
                        host_key: PublicKey::from_str(sec.host_key.as_str())
                            .map_err(|e: HexParseError| Error::from_reason(e.to_string()))?,
                        root: Hash256::from_str(sec.root.as_str())
                            .map_err(|e: HexParseError| Error::from_reason(e.to_string()))?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            offset: self.offset,
            length: self.length,
        })
    }
}

/// A cursor for paginating through objects.
#[napi(object)]
pub struct ObjectsCursor {
    pub id: String,
    pub after: DateTime<Utc>,
}

/// Application info.
#[napi(object)]
pub struct App {
    pub id: String,
    pub name: String,
    pub description: String,
    pub service_url: Option<String>,
    pub logo_url: Option<String>,
}

/// An account registered on the indexer.
#[napi(object)]
pub struct Account {
    pub account_key: String,
    pub max_pinned_data: BigInt,
    pub remaining_storage: BigInt,
    pub pinned_data: BigInt,
    pub pinned_size: BigInt,
    pub ready: bool,
    pub app: App,
    pub last_used: DateTime<Utc>,
}

impl From<sia_storage::Account> for Account {
    fn from(a: sia_storage::Account) -> Self {
        Self {
            account_key: a.account_key.to_string(),
            max_pinned_data: BigInt::from(a.max_pinned_data),
            remaining_storage: BigInt::from(a.remaining_storage),
            pinned_data: BigInt::from(a.pinned_data),
            pinned_size: BigInt::from(a.pinned_size),
            ready: a.ready,
            app: App {
                id: a.app.id.to_string(),
                name: a.app.name,
                description: a.app.description,
                service_url: a.app.service_url,
                logo_url: a.app.logo_url,
            },
            last_used: a.last_used,
        }
    }
}

/// Progress information about a successfully uploaded or downloaded shard.
#[napi(object)]
pub struct ShardProgress {
    pub host_key: String,
    pub shard_size: u32,
    pub shard_index: u32,
    pub slab_index: u32,
    pub elapsed: f64,
}

/// A Send-safe wrapper around a JS callback that converts it into a
/// `ThreadsafeFunction` during napi parameter extraction.
pub struct SendableCallback<T: ToNapiValue + 'static> {
    pub(crate) inner: ThreadsafeFunction<T, (), T, napi::Status, false, true>,
}

impl<T: ToNapiValue + 'static> FromNapiValue for SendableCallback<T> {
    unsafe fn from_napi_value(
        env: napi::sys::napi_env,
        value: napi::sys::napi_value,
    ) -> Result<Self> {
        let func = unsafe { Function::<'static, T, ()>::from_napi_value(env, value)? };
        let callback = func
            .build_threadsafe_function()
            .weak::<true>()
            .build()
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Self { inner: callback })
    }
}

impl SendableCallback<ShardProgress> {
    fn into_shard_callback(self) -> sia_storage::ShardProgressCallback {
        Arc::new(move |p: sia_storage::ShardProgress| {
            self.inner.call(
                ShardProgress {
                    host_key: p.host_key.to_string(),
                    shard_size: p.shard_size as u32,
                    shard_index: p.shard_index as u32,
                    slab_index: p.slab_index as u32,
                    elapsed: p.elapsed.as_millis() as f64,
                },
                ThreadsafeFunctionCallMode::NonBlocking,
            );
        })
    }
}

/// Upload options.
#[napi(object, object_to_js = false)]
#[derive(Default)]
pub struct UploadOptions {
    pub max_inflight: Option<u32>,
    pub data_shards: Option<u8>,
    pub parity_shards: Option<u8>,
    #[napi(ts_type = "(progress: ShardProgress) => void")]
    pub on_shard_uploaded: Option<SendableCallback<ShardProgress>>,
}

impl From<UploadOptions> for sia_storage::UploadOptions {
    fn from(val: UploadOptions) -> Self {
        let mut options = sia_storage::UploadOptions::default();
        options.data_shards = val.data_shards.unwrap_or(options.data_shards);
        options.parity_shards = val.parity_shards.unwrap_or(options.parity_shards);
        options.max_inflight = val
            .max_inflight
            .map(|v| v as usize)
            .unwrap_or(options.max_inflight);
        options.shard_uploaded = val.on_shard_uploaded.map(|cb| cb.into_shard_callback());
        options
    }
}

/// A Send-safe wrapper around `UploadOptions` that converts the JS callback
/// into a `ThreadsafeFunction` during napi parameter extraction.
pub struct SendableUploadOptions(pub(crate) sia_storage::UploadOptions);

impl FromNapiValue for SendableUploadOptions {
    unsafe fn from_napi_value(
        env: napi::sys::napi_env,
        value: napi::sys::napi_value,
    ) -> Result<Self> {
        let opts = unsafe { UploadOptions::from_napi_value(env, value)? };
        Ok(Self(opts.into()))
    }
}

/// Download options.
#[napi(object, object_to_js = false)]
pub struct DownloadOptions {
    pub max_inflight: Option<u8>,
    pub offset: Option<BigInt>,
    pub length: Option<BigInt>,
    #[napi(ts_type = "(progress: ShardProgress) => void")]
    pub on_shard_downloaded: Option<SendableCallback<ShardProgress>>,
}

impl TryFrom<DownloadOptions> for sia_storage::DownloadOptions {
    type Error = napi::Error;

    fn try_from(val: DownloadOptions) -> Result<Self> {
        let mut options = sia_storage::DownloadOptions::default();
        if let Some(max_inflight) = val.max_inflight {
            options.max_inflight = max_inflight as usize;
        }
        if let Some(offset) = val.offset {
            let (signed, offset, lossless) = offset.get_u64();
            if signed {
                return Err(Error::from_reason("offset must be non-negative"));
            } else if !lossless {
                return Err(Error::from_reason("offset too large"));
            }
            options.offset = offset;
        }
        if let Some(length) = val.length {
            let (signed, length, lossless) = length.get_u64();
            if signed {
                return Err(Error::from_reason("length must be non-negative"));
            } else if !lossless {
                return Err(Error::from_reason("length too large"));
            }
            options.length = Some(length);
        }
        options.shard_downloaded = val.on_shard_downloaded.map(|cb| cb.into_shard_callback());
        Ok(options)
    }
}

/// An object pinned to an indexer.
#[napi]
pub struct PinnedObject {
    inner: Mutex<sia_storage::Object>,
}

impl PinnedObject {
    fn object(&self) -> sia_storage::Object {
        self.inner.lock().unwrap().clone()
    }
}

impl Default for PinnedObject {
    fn default() -> Self {
        Self::new()
    }
}

#[napi]
impl PinnedObject {
    /// Creates a new empty object.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(sia_storage::Object::default()),
        }
    }

    /// Opens a sealed object using the provided app key.
    #[napi(factory)]
    pub fn open(app_key: &AppKey, sealed: SealedObject) -> Result<Self> {
        let sealed: sia_storage::SealedObject = sealed.try_into()?;
        let obj = sealed
            .open(&app_key.0)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Self {
            inner: Mutex::new(obj),
        })
    }

    /// Seals the object for offline storage.
    #[napi]
    pub fn seal(&self, app_key: &AppKey) -> SealedObject {
        let inner = self.inner.lock().unwrap();
        SealedObject::from(inner.seal(&app_key.0))
    }

    /// Returns the object's ID.
    #[napi]
    pub fn id(&self) -> String {
        self.inner.lock().unwrap().id().to_string()
    }

    /// Returns the total size of the object.
    #[napi]
    pub fn size(&self) -> BigInt {
        BigInt::from(self.inner.lock().unwrap().size())
    }

    /// Returns the total encoded size after erasure coding.
    #[napi]
    pub fn encoded_size(&self) -> BigInt {
        BigInt::from(self.inner.lock().unwrap().encoded_size())
    }

    /// Returns the slabs that make up the object.
    #[napi]
    pub fn slabs(&self) -> Vec<Slab> {
        self.inner
            .lock()
            .unwrap()
            .slabs()
            .iter()
            .cloned()
            .map(|s| s.into())
            .collect()
    }

    /// Returns the metadata associated with the object.
    #[napi]
    pub fn metadata(&self) -> Buffer {
        Buffer::from(self.inner.lock().unwrap().metadata.clone())
    }

    /// Updates the metadata associated with the object.
    #[napi]
    pub fn update_metadata(&self, metadata: Buffer) {
        self.inner.lock().unwrap().metadata = metadata.to_vec();
    }

    /// Returns the time the object was created (ms since epoch).
    #[napi]
    pub fn created_at(&self) -> DateTime<Utc> {
        *self.inner.lock().unwrap().created_at()
    }

    /// Returns the time the object was last updated (ms since epoch).
    #[napi]
    pub fn updated_at(&self) -> DateTime<Utc> {
        *self.inner.lock().unwrap().updated_at()
    }
}

enum PackedUploadAction {
    Add(
        io::NapiStreamReader,
        oneshot::Sender<std::result::Result<u64, sia_storage::UploadError>>,
    ),
    Finalize(
        oneshot::Sender<std::result::Result<Vec<sia_storage::Object>, sia_storage::UploadError>>,
    ),
}

/// A packed upload allows multiple objects to be uploaded together in a single
/// upload. This can be more efficient than individual uploads for many small
/// objects since they share slabs.
#[napi]
pub struct PackedUpload {
    upload_task: tokio::task::JoinHandle<()>,
    tx: mpsc::Sender<PackedUploadAction>,
    slab_size: u64,
    length: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
}

#[napi]
impl PackedUpload {
    /// Returns the number of bytes remaining until reaching the optimal
    /// packed size. Adding objects larger than this will start a new slab.
    #[napi]
    pub fn remaining(&self) -> BigInt {
        let length = self.length.load(Ordering::Acquire);
        let remaining = if length == 0 {
            self.slab_size
        } else {
            (self.slab_size - (length % self.slab_size)) % self.slab_size
        };
        BigInt::from(remaining)
    }

    /// Returns the number of bytes added so far.
    #[napi]
    pub fn length(&self) -> BigInt {
        BigInt::from(self.length.load(Ordering::Acquire))
    }

    /// Returns the number of slabs in the upload.
    #[napi]
    pub fn slabs(&self) -> BigInt {
        BigInt::from(self.length.load(Ordering::Acquire).div_ceil(self.slab_size))
    }

    /// Adds a new object to the upload. The data will be read until EOF and
    /// packed into the upload. Call `finalize()` after all objects have been added.
    #[napi(ts_args_type = "stream: ReadableStream")]
    pub async fn add(&self, stream: SendableReader) -> Result<BigInt> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::from_reason("upload already closed"));
        }
        let (add_tx, add_rx) = oneshot::channel();
        self.tx
            .send(PackedUploadAction::Add(stream.0, add_tx))
            .await
            .map_err(|_| Error::from_reason("upload closed"))?;
        let size = add_rx
            .await
            .map_err(|_| Error::from_reason("upload closed"))?
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(BigInt::from(size))
    }

    /// Cancels the upload.
    #[napi]
    pub async fn cancel(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Err(Error::from_reason("upload already closed"));
        }
        self.upload_task.abort();
        Ok(())
    }

    /// Finalizes the upload and returns the resulting objects. Each object
    /// must be pinned separately with `sdk.pinObject()`.
    #[napi]
    pub async fn finalize(&self) -> Result<Vec<PinnedObject>> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Err(Error::from_reason("upload already closed"));
        }
        let (finalize_tx, finalize_rx) = oneshot::channel();
        self.tx
            .send(PackedUploadAction::Finalize(finalize_tx))
            .await
            .map_err(|_| Error::from_reason("upload closed"))?;
        let objects = finalize_rx
            .await
            .map_err(|_| Error::from_reason("upload closed"))?
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(objects
            .into_iter()
            .map(|o| PinnedObject {
                inner: Mutex::new(o),
            })
            .collect())
    }
}

#[napi]
pub struct Sdk {
    pub(crate) inner: sia_storage::Sdk,
}

#[napi]
impl Sdk {
    /// Returns the application key used by the SDK.
    #[napi]
    pub fn app_key(&self) -> AppKey {
        AppKey(self.inner.app_key().clone())
    }

    /// Creates a new packed upload for efficiently uploading multiple small
    /// objects together. Returns a `PackedUpload` handle.
    #[napi(ts_args_type = "options?: UploadOptions")]
    pub fn upload_packed(&self, options: Option<SendableUploadOptions>) -> PackedUpload {
        let options: sia_storage::UploadOptions = options.map(|o| o.0).unwrap_or_default();
        let sdk = self.inner.clone();
        let length = Arc::new(AtomicU64::new(0));
        let closed = Arc::new(AtomicBool::new(false));
        let (action_tx, mut action_rx) = mpsc::channel(10);
        let slab_size = sia_storage::encoded_size(1, options.data_shards, options.parity_shards);
        let task_length = length.clone();
        let upload_task = spawn(async move {
            let mut packed_upload = sdk.upload_packed(options);

            while let Some(action) = action_rx.recv().await {
                match action {
                    PackedUploadAction::Add(reader, add_tx) => {
                        let res = packed_upload
                            .add(reader)
                            .await
                            .map_err(sia_storage::UploadError::from);
                        if let Ok(size) = res {
                            task_length.fetch_add(size, Ordering::AcqRel);
                        }
                        let _ = add_tx.send(res);
                    }
                    PackedUploadAction::Finalize(finalize_tx) => {
                        let result = packed_upload.finalize().await;
                        let _ = finalize_tx.send(result);
                        return;
                    }
                }
            }
        });

        PackedUpload {
            upload_task,
            tx: action_tx,
            slab_size,
            length,
            closed,
        }
    }

    /// Uploads data to the Sia network.
    ///
    /// Pass a new `PinnedObject` for new uploads. To resume a previous upload,
    /// pass the object returned from the earlier call. Appending data changes
    /// an object's ID. It must be re-pinned afterward and any references to
    /// the previous ID must be updated.
    #[napi(ts_args_type = "object: PinnedObject, stream: ReadableStream, options?: UploadOptions")]
    pub async fn upload(
        &self,
        object: &PinnedObject,
        stream: SendableReader,
        options: Option<SendableUploadOptions>,
    ) -> Result<PinnedObject> {
        let options = options.map(|o| o.0).unwrap_or_default();
        let inner = object.inner.lock().unwrap().clone();
        let obj = self
            .inner
            .clone()
            .upload(inner, stream.0, options)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(PinnedObject {
            inner: Mutex::new(obj),
        })
    }

    /// Downloads an object from the Sia network, returning a `ReadableStream`
    /// of the object's data.
    #[napi(ts_return_type = "ReadableStream")]
    pub fn download(
        &self,
        env: Env,
        object: &PinnedObject,
        options: Option<DownloadOptions>,
    ) -> Result<ReadableStream<'_, Buffer>> {
        let object = object.object();
        let download_opts: sia_storage::DownloadOptions = options
            .map(|o| o.try_into())
            .transpose()?
            .unwrap_or_default();

        let stream = within_runtime_if_available(|| {
            let reader = self
                .inner
                .download(&object, download_opts)
                .map_err(|e| Error::from_reason(e.to_string()))?;
            Ok::<_, Error>(io::AsyncReadStream::new(reader).map(|r| {
                r.map(Buffer::from)
                    .map_err(|e| Error::from_reason(e.to_string()))
            }))
        })?;
        ReadableStream::new(&env, stream)
    }

    /// Returns a list of all usable hosts.
    #[napi]
    pub async fn hosts(&self) -> Result<Vec<Host>> {
        let hosts = self
            .inner
            .hosts(Default::default())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(hosts.into_iter().map(|h| h.into()).collect())
    }

    /// Returns object events from the indexer for syncing.
    #[napi]
    pub async fn object_events(
        &self,
        cursor: Option<ObjectsCursor>,
        limit: u32,
    ) -> Result<Vec<ObjectEvent>> {
        let cursor = match cursor {
            Some(c) => Some(sia_storage::ObjectsCursor {
                after: c.after,
                id: Hash256::from_str(c.id.as_str())
                    .map_err(|e: HexParseError| Error::from_reason(e.to_string()))?,
            }),
            None => None,
        };
        let objects = self
            .inner
            .object_events(cursor, Some(limit as usize))
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?
            .into_iter()
            .map(|event| ObjectEvent {
                id: event.id.to_string(),
                deleted: event.deleted,
                updated_at: event.updated_at,
                object: event.object.map(|o| PinnedObject {
                    inner: Mutex::new(o),
                }),
            })
            .collect();
        Ok(objects)
    }

    /// Updates the metadata of an object stored in the indexer.
    #[napi]
    pub async fn update_object_metadata(&self, object: &PinnedObject) -> Result<()> {
        let object = object.object();
        self.inner
            .update_object_metadata(&object)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Deletes an object from the indexer.
    #[napi]
    pub async fn delete_object(&self, key: String) -> Result<()> {
        let key = Hash256::from_str(key.as_str())
            .map_err(|e: HexParseError| Error::from_reason(e.to_string()))?;
        self.inner
            .delete_object(&key)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Returns metadata about a specific object.
    #[napi]
    pub async fn object(&self, key: String) -> Result<PinnedObject> {
        let key = Hash256::from_str(key.as_str())
            .map_err(|e: HexParseError| Error::from_reason(e.to_string()))?;
        let obj = self
            .inner
            .object(&key)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(PinnedObject {
            inner: Mutex::new(obj),
        })
    }

    /// Returns metadata about a slab.
    #[napi]
    pub async fn slab(&self, slab_id: String) -> Result<PinnedSlab> {
        let slab_id = Hash256::from_str(slab_id.as_str())
            .map_err(|e: HexParseError| Error::from_reason(e.to_string()))?;
        let slab = self
            .inner
            .slab(&slab_id)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(slab.into())
    }

    /// Unpins slabs not used by any object on the account.
    #[napi]
    pub async fn prune_slabs(&self) -> Result<()> {
        self.inner
            .prune_slabs()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Returns the current account.
    #[napi]
    pub async fn account(&self) -> Result<Account> {
        let account = self
            .inner
            .account()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(account.into())
    }

    /// Creates a signed URL for sharing an object.
    #[napi]
    pub fn share_object(
        &self,
        object: &PinnedObject,
        valid_until: DateTime<Utc>,
    ) -> Result<String> {
        let u = self
            .inner
            .share_object(&object.object(), valid_until)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(u.to_string())
    }

    /// Retrieves a shared object from a signed URL.
    #[napi]
    pub async fn shared_object(&self, shared_url: String) -> Result<PinnedObject> {
        let shared_url =
            sia_storage::Url::parse(&shared_url).map_err(|e| Error::from_reason(e.to_string()))?;
        let object = self
            .inner
            .shared_object(shared_url)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(PinnedObject {
            inner: Mutex::new(object),
        })
    }

    /// Pins an object to the indexer.
    #[napi]
    pub async fn pin_object(&self, object: &PinnedObject) -> Result<()> {
        let object = object.object();
        self.inner
            .pin_object(&object)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}

/// Calculates the encoded size of data given the original size and erasure coding parameters.
#[napi]
pub fn encoded_size(size: BigInt, data_shards: u8, parity_shards: u8) -> BigInt {
    let (_, size, _) = size.get_u64();
    sia_storage::encoded_size(size, data_shards, parity_shards).into()
}
