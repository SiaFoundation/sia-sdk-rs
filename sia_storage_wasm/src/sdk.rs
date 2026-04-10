use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::str::FromStr;
use std::task::{Context, Poll};

use js_sys::Uint8Array;
use sia_core::types::Hash256;
use sia_core::types::v2::Protocol;
use sia_storage::{self, HostQuery as StorageHostQuery, ObjectsCursor, SDK as StorageSdk};
use tokio::io::AsyncWrite;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;

use crate::app_key::AppKey;
use crate::helpers::{run_local, to_js_err};
use crate::object::PinnedObject;
use crate::packed::PackedUpload;
use crate::streaming::Upload;
use crate::types::{Account, DownloadOptions, Host, HostQuery, ObjectEvent, UploadOptions};

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
/// An AsyncWrite adapter that queues chunks into a ReadableStream controller.
struct StreamWriter {
    controller: web_sys::ReadableStreamDefaultController,
}

impl AsyncWrite for StreamWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let array = Uint8Array::from(buf);
        if let Err(e) = self.controller.enqueue_with_chunk(&array) {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "ReadableStream enqueue error: {e:?}"
            ))));
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
        self.controller.close().ok();
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
                    after: chrono::DateTime::from_timestamp(secs, nanos)
                        .ok_or_else(|| JsValue::from_str("invalid cursor timestamp"))?,
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
                // report size as -1 if not present
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

    /// Downloads an object and returns a `ReadableStream` of `Uint8Array` chunks.
    ///
    /// ```js
    /// // as a blob
    /// const stream = sdk.download(obj);
    /// const blob = await new Response(stream).blob();
    ///
    /// // as a stream
    /// for await (const chunk of sdk.download(obj)) {
    ///   console.log('got', chunk.length, 'bytes');
    /// }
    /// ```
    pub fn download(
        &self,
        object: &PinnedObject,
        options: Option<DownloadOptions>,
    ) -> Result<web_sys::ReadableStream, JsValue> {
        let sdk = self.0.clone();
        let obj = object.0.clone();
        let opts = options.map(|o| o.to_inner()).unwrap_or_default();

        let controller: Rc<RefCell<Option<web_sys::ReadableStreamDefaultController>>> =
            Rc::new(RefCell::new(None));
        let controller_clone = controller.clone();

        let start = Closure::once(move |ctrl: web_sys::ReadableStreamDefaultController| {
            *controller_clone.borrow_mut() = Some(ctrl);
        });

        let underlying_source = js_sys::Object::new();
        js_sys::Reflect::set(
            &underlying_source,
            &"start".into(),
            start.as_ref().unchecked_ref(),
        )?;
        start.forget();

        let stream = web_sys::ReadableStream::new_with_underlying_source(&underlying_source)?;

        let controller_for_task = controller.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let ctrl = controller_for_task.borrow().clone().unwrap();
            let mut writer = StreamWriter {
                controller: ctrl.clone(),
            };
            match run_local(sdk.download(&mut writer, &obj, opts)).await {
                Ok(()) => {
                    ctrl.close().ok();
                }
                Err(e) => {
                    let err = JsValue::from_str(&e.to_string());
                    ctrl.error_with_e(&err);
                }
            }
        });

        Ok(stream)
    }

    /// Starts an upload. Returns an `Upload` handle.
    /// Push data with `pushChunk()`, then call `finish()` to get the `PinnedObject`.
    ///
    /// Pass an existing `PinnedObject` to append new slabs to it, or `null`
    /// for a new upload. Appending changes the object's ID — the caller must
    /// re-pin and update any references to the old ID.
    pub fn upload(&self, object: Option<PinnedObject>, options: Option<UploadOptions>) -> Upload {
        let (on_progress, opts) = match options {
            Some(mut o) => {
                let cb = o.on_progress.take();
                (cb, o.to_inner())
            }
            None => (None, sia_storage::UploadOptions::default()),
        };
        let obj = object.map(|p| p.0).unwrap_or_default();
        let (reader, writer) = tokio::io::simplex(1024 * 1024);
        Upload::new(writer, reader, self.0.clone(), obj, opts, on_progress)
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
        let valid_until = chrono::DateTime::from_timestamp(secs, nanos)
            .ok_or_else(|| JsValue::from_str("invalid timestamp"))?;
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
