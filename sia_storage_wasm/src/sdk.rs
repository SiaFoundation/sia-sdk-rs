use std::rc::Rc;
use std::str::FromStr;

use sia_core::types::v2::Protocol;
use sia_core::types::Hash256;
use sia_storage::{self, HostQuery as StorageHostQuery, ObjectsCursor, SDK as StorageSdk};
use tokio::sync::mpsc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::app_key::AppKey;
use crate::helpers::*;
use crate::object::PinnedObject;
use crate::streaming::{StreamingDownload, StreamingUpload};
use crate::types::{DownloadOptions, HostQuery, UploadOptions};

/// The main Sia storage SDK. Provides methods for uploading, downloading,
/// and managing objects on the Sia storage network via an indexer.
///
/// # Uploading
///
/// Two upload methods are available:
///
/// - **`upload(data)`** — pass the entire file as a `Uint8Array`. Simple, but
///   the full file must fit in WASM linear memory (~1.5 GB practical limit).
///   Best for files under ~500 MB.
///
/// - **`uploadStreaming()`** — returns a `StreamingUpload` handle. Push data
///   incrementally with `pushChunk()`, then call `finish()`. The SDK begins
///   uploading as chunks arrive — the full file never needs to be in memory
///   at once. Required for large files.
///
/// Both return an unpinned `PinnedObject` — call `pinObject()` afterward to
/// persist it on the indexer.
///
/// # Downloading
///
/// Two download methods are available:
///
/// - **`download(object)`** — returns the entire file as a `Uint8Array`.
///   Simple, but the full file must fit in WASM memory. Best for small files.
///
/// - **`downloadStreaming(object)`** — returns a `StreamingDownload` handle.
///   Call `readChunk()` in a loop until it returns `null`. Each chunk is up
///   to 256 KiB of decoded data. Use for large files, video playback, or
///   writing directly to disk via the File System Access API.
///
/// Both require a `PinnedObject` handle from `object()` or `upload()`.
#[wasm_bindgen]
pub struct Sdk(Rc<StorageSdk>);

impl Sdk {
    pub(crate) fn new(sdk: StorageSdk) -> Self {
        Self(Rc::new(sdk))
    }
}

#[wasm_bindgen]
impl Sdk {
    /// Returns the AppKey used by this SDK instance.
    #[wasm_bindgen(js_name = "appKey")]
    pub fn app_key(&self) -> AppKey {
        AppKey(self.0.app_key().clone())
    }

    /// Returns account information from the indexer.
    pub async fn account(&self) -> Result<JsValue, JsValue> {
        let sdk = self.0.clone();
        let a = sdk.account().await.map_err(to_js_err)?;
        to_js_value(&AccountInfo {
            account_key: a.account_key.to_string(),
            max_pinned_data: a.max_pinned_data,
            remaining_storage: a.remaining_storage,
            pinned_data: a.pinned_data,
            pinned_size: a.pinned_size,
            ready: a.ready,
            app_name: a.app.name,
            app_description: a.app.description,
        })
    }

    /// Returns a list of usable hosts, optionally filtered by a HostQuery.
    pub async fn hosts(&self, query: Option<HostQuery>) -> Result<JsValue, JsValue> {
        let sdk = self.0.clone();
        let q = query
            .map(|q| q.to_inner())
            .unwrap_or(StorageHostQuery {
                protocol: Some(Protocol::QUIC),
                ..Default::default()
            });
        let hosts = sdk.hosts(q).await.map_err(to_js_err)?;
        let list: Vec<HostInfo> = hosts
            .into_iter()
            .map(|h| HostInfo {
                public_key: h.public_key.to_string(),
                country_code: h.country_code,
                good_for_upload: h.good_for_upload,
            })
            .collect();
        to_js_value(&list)
    }

    /// Retrieves an object from the indexer by its hex ID.
    pub async fn object(&self, key_hex: &str) -> Result<JsValue, JsValue> {
        let key = Hash256::from_str(key_hex).map_err(to_js_err)?;
        let sdk = self.0.clone();
        let obj = sdk.object(&key).await.map_err(to_js_err)?;
        to_js_value(&object_to_info(&obj))
    }

    /// Returns object events for syncing local state with the indexer.
    /// `cursor_after` is milliseconds since epoch (JS `Date.getTime()`).
    #[wasm_bindgen(js_name = "objectEvents")]
    pub async fn object_events(
        &self,
        cursor_id: Option<String>,
        cursor_after: Option<f64>,
        limit: u32,
    ) -> Result<JsValue, JsValue> {
        let cursor = match (cursor_id, cursor_after) {
            (Some(id), Some(after_ms)) => {
                let secs = (after_ms / 1000.0) as i64;
                let nanos = ((after_ms % 1000.0) * 1_000_000.0) as u32;
                Some(ObjectsCursor {
                    after: chrono::DateTime::from_timestamp(secs, nanos)
                        .unwrap_or_default(),
                    id: Hash256::from_str(&id).map_err(to_js_err)?,
                })
            }
            _ => None,
        };
        let sdk = self.0.clone();
        let events = sdk
            .object_events(cursor, Some(limit as usize))
            .await
            .map_err(to_js_err)?;
        let list: Vec<ObjectEventInfo> = events
            .into_iter()
            .map(|e| ObjectEventInfo {
                id: e.id.to_string(),
                deleted: e.deleted,
                updated_at: e.updated_at.timestamp(),
                object: e.object.as_ref().map(object_to_info),
            })
            .collect();
        to_js_value(&list)
    }

    /// Deletes an object from the indexer by its hex ID.
    #[wasm_bindgen(js_name = "deleteObject")]
    pub async fn delete_object(&self, key_hex: &str) -> Result<(), JsValue> {
        let key = Hash256::from_str(key_hex).map_err(to_js_err)?;
        let sdk = self.0.clone();
        sdk.delete_object(&key).await.map_err(to_js_err)
    }

    /// Uploads data and returns a PinnedObject handle. The object is NOT pinned
    /// automatically — call `pinObject()` afterward.
    ///
    /// The optional `onProgress` callback receives `(shardsUploaded)` each time
    /// a shard finishes uploading.
    #[wasm_bindgen(js_name = "upload")]
    pub async fn upload(
        &self,
        data: Vec<u8>,
        options: Option<UploadOptions>,
        on_progress: Option<js_sys::Function>,
    ) -> Result<PinnedObject, JsValue> {
        let sdk = self.0.clone();
        let cursor = std::io::Cursor::new(data);
        let mut opts = options.map(|o| o.to_inner()).unwrap_or_default();

        let (tx, mut rx) = mpsc::unbounded_channel();
        opts.shard_uploaded = Some(tx);

        let obj = run_local(async {
            if let Some(cb) = on_progress {
                tokio::task::spawn_local(async move {
                    let mut count: u32 = 0;
                    while rx.recv().await.is_some() {
                        count += 1;
                        let _ = cb.call1(&JsValue::NULL, &JsValue::from(count));
                    }
                });
            }
            sdk.upload(cursor, opts).await
        })
        .await
        .map_err(to_js_err)?;
        Ok(PinnedObject(obj))
    }

    /// Pins an object to the indexer so it persists beyond temporary storage.
    #[wasm_bindgen(js_name = "pinObject")]
    pub async fn pin_object(&self, object: &PinnedObject) -> Result<(), JsValue> {
        let sdk = self.0.clone();
        sdk.pin_object(&object.0).await.map_err(to_js_err)
    }

    /// Updates an object's metadata on the indexer.
    #[wasm_bindgen(js_name = "updateObjectMetadata")]
    pub async fn update_object_metadata(&self, object: &PinnedObject) -> Result<(), JsValue> {
        let sdk = self.0.clone();
        sdk.update_object_metadata(&object.0)
            .await
            .map_err(to_js_err)
    }

    /// Downloads an object and returns the raw bytes. The entire file is
    /// buffered in WASM memory — use `downloadStreaming()` for large files.
    pub async fn download(
        &self,
        object: &PinnedObject,
        options: Option<DownloadOptions>,
    ) -> Result<Vec<u8>, JsValue> {
        let sdk = self.0.clone();
        let opts = options.map(|o| o.to_inner()).unwrap_or_default();
        let size = object.0.size() as usize;
        let mut buf = Vec::with_capacity(size);
        run_local(sdk.download(&mut buf, &object.0, opts))
            .await
            .map_err(to_js_err)?;
        Ok(buf)
    }

    /// Starts a streaming upload. Returns a `StreamingUpload` handle.
    /// Push data incrementally with `pushChunk()`, then call `finish()`.
    #[wasm_bindgen(js_name = "uploadStreaming")]
    pub fn upload_streaming(&self, options: Option<UploadOptions>) -> StreamingUpload {
        let opts = options.map(|o| o.to_inner()).unwrap_or_default();
        let (reader, writer) = tokio::io::simplex(1024 * 1024);
        StreamingUpload::new(writer, reader, self.0.clone(), opts)
    }

    /// Starts a streaming download. Returns a `StreamingDownload` handle.
    /// Call `readChunk()` in a loop until it returns `null`.
    #[wasm_bindgen(js_name = "downloadStreaming")]
    pub fn download_streaming(
        &self,
        object: &PinnedObject,
        options: Option<DownloadOptions>,
    ) -> StreamingDownload {
        let opts = options.map(|o| o.to_inner()).unwrap_or_default();
        let (reader, writer) = tokio::io::simplex(1024 * 1024);
        let sdk = self.0.clone();
        let obj_clone = object.0.clone();

        let download_promise = future_to_promise(async move {
            let mut writer = writer;
            run_local(sdk.download(&mut writer, &obj_clone, opts))
                .await
                .map_err(to_js_err)?;
            Ok(JsValue::UNDEFINED)
        });

        StreamingDownload::new(reader, download_promise)
    }

    /// Prunes unused slabs from the indexer.
    #[wasm_bindgen(js_name = "pruneSlabs")]
    pub async fn prune_slabs(&self) -> Result<(), JsValue> {
        let sdk = self.0.clone();
        sdk.prune_slabs().await.map_err(to_js_err)
    }
}
