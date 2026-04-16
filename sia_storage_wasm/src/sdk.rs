use std::str::FromStr;

use sia_core::types::Hash256;
use sia_core::types::v2::Protocol;
use sia_storage::{self, HostQuery as StorageHostQuery, ObjectsCursor, SDK as StorageSdk};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use wasm_bindgen::prelude::*;

use crate::app_key::AppKey;
use crate::helpers::to_js_err;
use crate::object::PinnedObject;
use crate::packed::PackedUpload;
use crate::run_local;
use crate::types::{
    Account, DownloadOptions, Host, HostQuery, ObjectEvent, PinnedSlab, UploadOptions,
};

/// The main Sia storage SDK. Provides methods for uploading, downloading,
/// and managing objects on the Sia storage network via an indexer.
#[wasm_bindgen]
pub struct Sdk {
    inner: StorageSdk,
}

impl Sdk {
    pub(crate) fn new(inner: StorageSdk) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl Sdk {
    /// Returns the AppKey used by this SDK instance.
    #[wasm_bindgen(js_name = "appKey")]
    pub fn app_key(&self) -> AppKey {
        AppKey(self.inner.app_key().clone())
    }

    /// Returns account information from the indexer.
    pub async fn account(&self) -> Result<Account, JsError> {
        let sdk = self.inner.clone();
        let a = run_local(async move { sdk.account().await })
            .await
            .map_err(to_js_err)?;
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
    pub async fn hosts(&self, query: Option<HostQuery>) -> Result<Vec<Host>, JsError> {
        let sdk = self.inner.clone();
        let q = query.map(|q| q.into()).unwrap_or(StorageHostQuery {
            protocol: Some(Protocol::QUIC),
            ..Default::default()
        });
        let hosts = run_local(async move { sdk.hosts(q).await })
            .await
            .map_err(to_js_err)?;
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
    pub async fn object(&self, key_hex: &str) -> Result<PinnedObject, JsError> {
        let sdk = self.inner.clone();
        let key = Hash256::from_str(key_hex).map_err(to_js_err)?;
        let obj = run_local(async move { sdk.object(&key).await })
            .await
            .map_err(to_js_err)?;
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
    ) -> Result<Vec<ObjectEvent>, JsError> {
        let sdk = self.inner.clone();
        let cursor = match (cursor_id, cursor_after) {
            (Some(id), Some(after_ms)) => {
                let secs = (after_ms / 1000.0) as i64;
                let nanos = ((after_ms % 1000.0) * 1_000_000.0) as u32;
                Some(ObjectsCursor {
                    after: chrono::DateTime::from_timestamp(secs, nanos)
                        .ok_or_else(|| JsError::new("invalid cursor timestamp"))?,
                    id: Hash256::from_str(&id).map_err(to_js_err)?,
                })
            }
            _ => None,
        };
        let events =
            run_local(async move { sdk.object_events(cursor, Some(limit as usize)).await })
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

    /// Retrieves a pinned slab from the indexer by its hex ID.
    pub async fn slab(&self, slab_id: &str) -> Result<PinnedSlab, JsError> {
        let sdk = self.inner.clone();
        let id = Hash256::from_str(slab_id).map_err(to_js_err)?;
        let slab = run_local(async move { sdk.slab(&id).await })
            .await
            .map_err(to_js_err)?;
        Ok(slab.into())
    }

    /// Deletes an object from the indexer by its hex ID.
    #[wasm_bindgen(js_name = "deleteObject")]
    pub async fn delete_object(&self, key_hex: &str) -> Result<(), JsError> {
        let sdk = self.inner.clone();
        let key = Hash256::from_str(key_hex).map_err(to_js_err)?;
        run_local(async move { sdk.delete_object(&key).await })
            .await
            .map_err(to_js_err)
    }

    /// Pins an object to the indexer so it persists beyond temporary storage.
    #[wasm_bindgen(js_name = "pinObject")]
    pub async fn pin_object(&self, object: &PinnedObject) -> Result<(), JsError> {
        let sdk = self.inner.clone();
        let obj = object.0.clone();
        run_local(async move { sdk.pin_object(&obj).await })
            .await
            .map_err(to_js_err)
    }

    /// Updates an object's metadata on the indexer.
    #[wasm_bindgen(js_name = "updateObjectMetadata")]
    pub async fn update_object_metadata(&self, object: &PinnedObject) -> Result<(), JsError> {
        let sdk = self.inner.clone();
        let obj = object.0.clone();
        run_local(async move { sdk.update_object_metadata(&obj).await })
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
    ) -> Result<web_sys::ReadableStream, JsError> {
        const CHUNK_SIZE: usize = 1 << 18; // matches sia_storage chunk size for optimal performance
        let obj = object.0.clone();
        let opts = options.map(|o| o.into()).unwrap_or_default();
        let download = self.inner.download(&obj, opts).map_err(to_js_err)?;
        Ok(wasm_streams::ReadableStream::from_async_read(download.compat(), CHUNK_SIZE).into_raw())
    }

    /// Uploads data from a `ReadableStream` to the Sia network.
    ///
    /// Pass an existing `PinnedObject` to append new slabs to it, or `null`
    /// for a new upload. Appending changes the object's ID — the caller must
    /// re-pin and update any references to the old ID.
    ///
    /// ```js
    /// const obj = await sdk.upload(file.stream(), null, options);
    /// await sdk.pinObject(obj);
    /// ```
    pub async fn upload(
        &self,
        source: web_sys::ReadableStream,
        object: PinnedObject,
        options: Option<UploadOptions>,
    ) -> Result<PinnedObject, JsError> {
        let sdk = self.inner.clone();
        let opts = options.map(|o| o.into()).unwrap_or_default();
        let obj = object.0;
        let reader = wasm_streams::ReadableStream::from_raw(source)
            .into_async_read()
            .compat();
        let result = run_local(async move { sdk.upload(obj, reader, opts).await })
            .await
            .map_err(to_js_err)?;
        Ok(PinnedObject(result))
    }

    /// Starts a packed upload for efficiently uploading multiple small objects.
    /// Objects smaller than the slab size (~40 MiB) are packed into shared slabs
    /// to avoid wasting storage. Call `add(data)` for each object, then
    /// `finalize()` to get the resulting `PinnedObject` handles.
    #[wasm_bindgen(js_name = "uploadPacked")]
    pub fn upload_packed(&self, options: Option<UploadOptions>) -> PackedUpload {
        let opts = options.map(|o| o.into()).unwrap_or_default();
        PackedUpload::new(self.inner.upload_packed(opts))
    }

    /// Generates a signed share URL for an object. Anyone with the URL can
    /// download and decrypt the object until `valid_until_ms` (milliseconds
    /// since epoch, i.e. `Date.getTime()`).
    #[wasm_bindgen(js_name = "shareObject")]
    pub fn share_object(
        &self,
        object: &PinnedObject,
        valid_until_ms: f64,
    ) -> Result<String, JsError> {
        let secs = (valid_until_ms / 1000.0) as i64;
        let nanos = ((valid_until_ms % 1000.0) * 1_000_000.0) as u32;
        let valid_until = chrono::DateTime::from_timestamp(secs, nanos)
            .ok_or_else(|| JsError::new("invalid timestamp"))?;
        let url = self
            .inner
            .share_object(&object.0, valid_until)
            .map_err(to_js_err)?;
        Ok(url.to_string())
    }

    /// Resolves a share URL (sia://...) and returns the shared object.
    /// The encryption key is extracted from the URL fragment (never sent
    /// to the indexer).
    #[wasm_bindgen(js_name = "sharedObject")]
    pub async fn shared_object(&self, share_url: &str) -> Result<PinnedObject, JsError> {
        let sdk = self.inner.clone();
        let url = share_url.to_string();
        let obj = run_local(async move { sdk.shared_object(url).await })
            .await
            .map_err(to_js_err)?;
        Ok(PinnedObject(obj))
    }

    /// Prunes unused slabs from the indexer.
    #[wasm_bindgen(js_name = "pruneSlabs")]
    pub async fn prune_slabs(&self) -> Result<(), JsError> {
        let sdk = self.inner.clone();
        run_local(async move { sdk.prune_slabs().await })
            .await
            .map_err(to_js_err)
    }
}
