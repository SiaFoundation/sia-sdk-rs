use std::pin::Pin;
use std::rc::Rc;
use std::str::FromStr;
use std::task::{Context, Poll};

use js_sys::Uint8Array;
use sia_core::types::Hash256;
use sia_core::types::v2::Protocol;
use sia_storage::{
    self, DownloadOptions as StorageDownloadOptions, HostQuery as StorageHostQuery, ObjectsCursor,
    SDK as StorageSdk,
};
use tokio::io::AsyncWrite;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

use crate::app_key::AppKey;
use crate::helpers::{run_local, to_js_err};
use crate::object::PinnedObject;
use crate::packed::PackedUpload;
use crate::streaming::Upload;
use crate::types::{Account, DownloadOptions, Host, HostQuery, ObjectEvent, UploadOptions};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "(chunk: Uint8Array) => void")]
    pub type OnChunkCallback;

    #[wasm_bindgen(typescript_type = "(bytesDownloaded: number, totalBytes: number) => void")]
    pub type OnProgressCallback;

    #[wasm_bindgen(typescript_type = "(shardsUploaded: number) => void")]
    pub type OnShardProgressCallback;
}

/// The main Sia storage SDK. Provides methods for uploading, downloading,
/// and managing objects on the Sia storage network via an indexer.
///
/// # Uploading
///
/// Two upload methods are available:
///
/// - **`upload(options?)`** — returns a `Upload` handle. Push data
///   with `pushChunk()`, then call `finish()` to get the `PinnedObject`.
///   Works for any size — the full file never needs to be in memory at once.
///   Each slab holds up to 40 MiB of data (10 data shards × 4 MiB sectors).
///   Files smaller than this still consume one full slab (120 MiB on-network
///   with default 10+20 redundancy).
///
/// - **`uploadPacked(options?)`** — returns a `PackedUpload` handle for
///   efficiently uploading multiple small objects together. Call `add(data)`
///   for each object, then `finalize()` to get the resulting `PinnedObject`
///   handles. Objects are packed into shared slabs so a 1 KiB file doesn't
///   waste an entire 120 MiB slab.
///
/// `upload().finish()` returns a single `PinnedObject`.
/// `uploadPacked().finalize()` returns an array of `PinnedObject` handles.
/// All must be pinned with `pinObject()` afterward to persist on the indexer.
///
/// # Downloading
///
/// Two download methods are available:
///
/// - **`download(object)`** — returns the entire file as a `Uint8Array`.
///   Simple, but the full file must fit in WASM memory. Best for small files.
///
/// - **`downloadStreaming(object, onChunk, onProgress?, options?)`** — calls
///   `onChunk(chunk: Uint8Array)` with each decoded chunk as it arrives.
///   The optional `onProgress(bytesDownloaded, totalBytes)` callback reports
///   progress. Use for large files, video playback, or writing directly to
///   disk via the File System Access API.
///
/// Both require a `PinnedObject` handle from `object()` or `upload()`.
///
/// An AsyncWrite adapter that calls a JS callback with each chunk of decoded
/// data. Used by `download_streaming` to push bytes to JS as they arrive
/// without buffering the entire file.
struct ChunkWriter {
    callback: js_sys::Function,
    written: u64,
    total: f64,
    on_progress: Option<js_sys::Function>,
}

impl AsyncWrite for ChunkWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let array = Uint8Array::from(buf);
        let _ = self.callback.call1(&JsValue::NULL, &array);
        self.written += buf.len() as u64;
        if let Some(ref cb) = self.on_progress {
            let _ = cb.call2(
                &JsValue::NULL,
                &JsValue::from(self.written as f64),
                &JsValue::from(self.total),
            );
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

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
    pub async fn account(&self) -> Result<Account, JsValue> {
        let sdk = self.0.clone();
        let a = sdk.account().await.map_err(to_js_err)?;
        Ok(Account {
            account_key: a.account_key.to_string(),
            max_pinned_data: a.max_pinned_data as f64,
            remaining_storage: a.remaining_storage as f64,
            pinned_data: a.pinned_data as f64,
            pinned_size: a.pinned_size as f64,
            ready: a.ready,
            app_name: a.app.name,
            app_description: a.app.description,
        })
    }

    /// Returns a list of usable hosts, optionally filtered by a HostQuery.
    pub async fn hosts(&self, query: Option<HostQuery>) -> Result<Vec<Host>, JsValue> {
        let sdk = self.0.clone();
        let q = query.map(|q| q.to_inner()).unwrap_or(StorageHostQuery {
            protocol: Some(Protocol::QUIC),
            ..Default::default()
        });
        let hosts = sdk.hosts(q).await.map_err(to_js_err)?;
        Ok(hosts
            .into_iter()
            .map(|h| Host {
                public_key: h.public_key.to_string(),
                country_code: h.country_code,
                good_for_upload: h.good_for_upload,
            })
            .collect())
    }

    /// Retrieves an object from the indexer by its hex ID.
    /// Returns a `PinnedObject` handle for use with download, share, seal, etc.
    pub async fn object(&self, key_hex: &str) -> Result<PinnedObject, JsValue> {
        let key = Hash256::from_str(key_hex).map_err(to_js_err)?;
        let sdk = self.0.clone();
        let obj = sdk.object(&key).await.map_err(to_js_err)?;
        Ok(PinnedObject(obj))
    }

    /// Returns object events for syncing local state with the indexer.
    /// `cursor_after` is milliseconds since epoch (JS `Date.getTime()`).
    #[wasm_bindgen(js_name = "objectEvents")]
    pub async fn object_events(
        &self,
        cursor_id: Option<String>,
        cursor_after: Option<f64>,
        limit: u32,
    ) -> Result<Vec<ObjectEvent>, JsValue> {
        let cursor = match (cursor_id, cursor_after) {
            (Some(id), Some(after_ms)) => {
                let secs = (after_ms / 1000.0) as i64;
                let nanos = ((after_ms % 1000.0) * 1_000_000.0) as u32;
                Some(ObjectsCursor {
                    after: chrono::DateTime::from_timestamp(secs, nanos).unwrap_or_default(),
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
        Ok(events
            .into_iter()
            .map(|e| ObjectEvent {
                id: e.id.to_string(),
                deleted: e.deleted,
                updated_at: e.updated_at.timestamp() as f64,
                size: e.object.as_ref().map(|o| o.size() as f64).unwrap_or(-1.0),
            })
            .collect())
    }

    /// Deletes an object from the indexer by its hex ID.
    #[wasm_bindgen(js_name = "deleteObject")]
    pub async fn delete_object(&self, key_hex: &str) -> Result<(), JsValue> {
        let key = Hash256::from_str(key_hex).map_err(to_js_err)?;
        let sdk = self.0.clone();
        sdk.delete_object(&key).await.map_err(to_js_err)
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
        let size = object.0.size();
        const MAX_DOWNLOAD: u64 = 1_536 * 1024 * 1024; // 1.5 GiB
        if size > MAX_DOWNLOAD {
            return Err(JsValue::from_str(&format!(
                "object too large for buffered download ({:.1} GiB). Use downloadStreaming() instead.",
                size as f64 / (1024.0 * 1024.0 * 1024.0)
            )));
        }
        let mut buf = Vec::with_capacity(size as usize);
        run_local(sdk.download(&mut buf, &object.0, opts))
            .await
            .map_err(to_js_err)?;
        Ok(buf)
    }

    /// Downloads a single slab by index, returning up to ~40 MiB of
    /// decrypted data. Use for parallel downloads across Web Workers
    /// or video seeking.
    #[wasm_bindgen(js_name = "downloadSlab")]
    pub async fn download_slab(
        &self,
        object: &PinnedObject,
        slab_index: u32,
    ) -> Result<Vec<u8>, JsValue> {
        let obj = &object.0;
        let slabs = obj.slabs();
        let idx = slab_index as usize;
        if idx >= slabs.len() {
            return Err(JsValue::from_str(&format!(
                "slab index {} out of range (object has {} slabs)",
                idx,
                slabs.len()
            )));
        }
        let offset: u64 = slabs[..idx].iter().map(|s| s.length as u64).sum();
        let length = slabs[idx].length;
        let mut buf = Vec::with_capacity(length as usize);
        let opts = StorageDownloadOptions {
            offset,
            length: Some(length as u64),
            ..Default::default()
        };
        let sdk = self.0.clone();
        run_local(sdk.download(&mut buf, obj, opts))
            .await
            .map_err(to_js_err)?;
        Ok(buf)
    }

    /// Starts an upload. Returns a `Upload` handle.
    /// Push data with `pushChunk()`, then call `finish()` to get the `PinnedObject`.
    pub fn upload(&self, options: Option<UploadOptions>) -> Upload {
        let opts = options.map(|o| o.to_inner()).unwrap_or_default();
        let (reader, writer) = tokio::io::simplex(1024 * 1024);
        Upload::new(writer, reader, self.0.clone(), opts)
    }

    /// Starts a packed upload for efficiently uploading multiple small objects.
    /// Objects smaller than the slab size (~40 MiB) are packed into shared slabs
    /// to avoid wasting storage. Call `add(data)` for each object, then
    /// `finalize()` to get the resulting `PinnedObject` handles.
    #[wasm_bindgen(js_name = "uploadPacked")]
    pub fn upload_packed(&self, options: Option<UploadOptions>) -> PackedUpload {
        let opts = options.map(|o| o.to_inner()).unwrap_or_default();
        PackedUpload::new(self.0.upload_packed(opts))
    }

    /// Downloads an object with streaming chunks via callbacks.
    ///
    /// The `on_chunk` callback receives each decoded chunk as a `Uint8Array`
    /// as it arrives. This avoids buffering the entire file in memory.
    ///
    /// The optional `on_progress` callback receives `(bytesDownloaded, totalBytes)`.
    #[wasm_bindgen(js_name = "downloadStreaming")]
    pub async fn download_streaming(
        &self,
        object: &PinnedObject,
        on_chunk: OnChunkCallback,
        on_progress: Option<OnProgressCallback>,
        options: Option<DownloadOptions>,
    ) -> Result<(), JsValue> {
        let sdk = self.0.clone();
        let obj = object.0.clone();
        let total = obj.size() as f64;
        let opts = options.map(|o| o.to_inner()).unwrap_or_default();

        let chunk_fn: js_sys::Function = on_chunk.unchecked_into();
        let progress_fn: Option<js_sys::Function> = on_progress.map(|p| p.unchecked_into());

        let mut writer = ChunkWriter {
            callback: chunk_fn,
            written: 0,
            total,
            on_progress: progress_fn,
        };

        run_local(sdk.download(&mut writer, &obj, opts))
            .await
            .map_err(to_js_err)?;
        Ok(())
    }

    /// Generates a signed share URL for an object. Anyone with the URL can
    /// download and decrypt the object until `valid_until_ms` (milliseconds
    /// since epoch, i.e. `Date.getTime()`).
    #[wasm_bindgen(js_name = "shareObject")]
    pub fn share_object(
        &self,
        object: &PinnedObject,
        valid_until_ms: f64,
    ) -> Result<String, JsValue> {
        let secs = (valid_until_ms / 1000.0) as i64;
        let nanos = ((valid_until_ms % 1000.0) * 1_000_000.0) as u32;
        let valid_until = chrono::DateTime::from_timestamp(secs, nanos).unwrap_or_default();
        let url = self
            .0
            .share_object(&object.0, valid_until)
            .map_err(to_js_err)?;
        Ok(url.to_string())
    }

    /// Resolves a share URL (sia://...) and returns the shared object.
    /// The encryption key is extracted from the URL fragment (never sent
    /// to the indexer).
    #[wasm_bindgen(js_name = "sharedObject")]
    pub async fn shared_object(&self, share_url: &str) -> Result<PinnedObject, JsValue> {
        let sdk = self.0.clone();
        let url = share_url.to_string();
        let obj = sdk.shared_object(url).await.map_err(to_js_err)?;
        Ok(PinnedObject(obj))
    }

    /// Prunes unused slabs from the indexer.
    #[wasm_bindgen(js_name = "pruneSlabs")]
    pub async fn prune_slabs(&self) -> Result<(), JsValue> {
        let sdk = self.0.clone();
        sdk.prune_slabs().await.map_err(to_js_err)
    }
}
