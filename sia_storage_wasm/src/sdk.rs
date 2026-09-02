use std::str::FromStr;

use js_sys::Reflect;
use sia_core::types::Hash256;
use sia_storage::{self, Sdk as StorageSdk};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tsify::Ts;
use wasm_bindgen::prelude::*;

use crate::app_key::AppKey;
use crate::helpers::to_js_err;
use crate::object::PinnedObject;
use crate::packed::PackedUpload;
use crate::run_local;
use crate::sharing::{KeyRecord, SharingKey};
use crate::stream_reader::js_stream_reader;
use crate::types::{
    self, HostQuery, ObjectEvent, download_options_from_js, ms_to_chrono,
    packed_upload_options_from_js, upload_options_from_js,
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
    /// Creates a sharing key. Attach objects to it with `Sdk.shareObject`.
    #[wasm_bindgen(js_name = "createSharingKey")]
    pub async fn create_sharing_key(
        &self,
        description: String,
        expires_at: Option<js_sys::Date>,
    ) -> Result<SharingKey, JsError> {
        let expires_at = expires_at.map(|d| ms_to_chrono(d.get_time())).transpose()?;
        let key = self
            .inner
            .create_sharing_key(sia_storage::SharingKeyOptions {
                description,
                expires_at,
            })
            .await
            .map_err(to_js_err)?;
        Ok(SharingKey::new(key))
    }

    /// Lists the account's sharing keys, most recently created first.
    #[wasm_bindgen(js_name = "sharingKeys")]
    pub async fn sharing_keys(&self, offset: u32, limit: u32) -> Result<Vec<KeyRecord>, JsError> {
        let keys = self
            .inner
            .sharing_keys(Some(offset as u64), Some(limit as u64))
            .await
            .map_err(to_js_err)?;
        Ok(keys.into_iter().map(KeyRecord::new).collect())
    }

    /// Fetches the indexer's record for a key, including its counts.
    #[wasm_bindgen(js_name = "sharingKey")]
    pub async fn sharing_key(&self, key: &SharingKey) -> Result<KeyRecord, JsError> {
        let record = self.inner.sharing_key(key.key()).await.map_err(to_js_err)?;
        Ok(KeyRecord::new(record))
    }

    /// Attaches an object to a sharing key, re-sealing its encryption keys under
    /// the key so recipients can decrypt it. Attaching an already-attached
    /// object replaces its re-sealed keys, so a failed call can be retried.
    #[wasm_bindgen(js_name = "shareObject")]
    pub async fn share_object(
        &self,
        key: &SharingKey,
        object: &PinnedObject,
    ) -> Result<(), JsError> {
        self.inner
            .share_object(key.key(), &object.0)
            .await
            .map_err(to_js_err)
    }

    /// Lists and decrypts a page of the objects a sharing key grants access to.
    #[wasm_bindgen(js_name = "sharedObjects")]
    pub async fn shared_objects(
        &self,
        key: &SharingKey,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<PinnedObject>, JsError> {
        let objects = self
            .inner
            .shared_objects(key.key(), Some(offset as u64), Some(limit as u64))
            .await
            .map_err(to_js_err)?;
        Ok(objects.into_iter().map(PinnedObject).collect())
    }

    /// Detaches an object from a sharing key, leaving the key and its other
    /// attachments in place.
    #[wasm_bindgen(js_name = "unshareObject")]
    pub async fn unshare_object(
        &self,
        key: &SharingKey,
        object: &PinnedObject,
    ) -> Result<(), JsError> {
        self.inner
            .unshare_object(key.key(), &object.0.id())
            .await
            .map_err(to_js_err)
    }

    /// Deletes a sharing key along with all of its attachments, revoking
    /// recipients' access. Account tokens already issued stay valid until they
    /// expire, so a download in flight can keep reading for up to five minutes.
    #[wasm_bindgen(js_name = "revokeSharingKey")]
    pub async fn revoke_sharing_key(&self, key: &SharingKey) -> Result<(), JsError> {
        self.inner
            .revoke_sharing_key(key.key())
            .await
            .map_err(to_js_err)
    }

    /// Returns the AppKey used by this SDK instance.
    #[wasm_bindgen(js_name = "appKey")]
    pub fn app_key(&self) -> AppKey {
        AppKey(self.inner.app_key().clone())
    }

    /// Returns account information from the indexer.
    #[wasm_bindgen(unchecked_return_type = "Account")]
    pub async fn account(&self) -> Result<JsValue, JsError> {
        let sdk = self.inner.clone();
        let a = run_local(async move { sdk.account().await })
            .await
            .map_err(to_js_err)?;
        let wrapped: types::Account = a.into();
        types::to_js(&wrapped)
    }

    /// Returns a list of usable hosts, optionally filtered by a HostQuery.
    #[wasm_bindgen(unchecked_return_type = "Host[]")]
    pub async fn hosts(&self, query: Option<Ts<HostQuery>>) -> Result<JsValue, JsError> {
        let sdk = self.inner.clone();
        let q = types::host_query_from_js(query)?;
        let hosts = run_local(async move { sdk.hosts(q).await })
            .await
            .map_err(to_js_err)?;
        types::to_js(&hosts)
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
    #[wasm_bindgen(js_name = "objectEvents")]
    pub async fn object_events(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ObjectsCursor | null | undefined")] cursor: JsValue,
        limit: u32,
    ) -> Result<Vec<ObjectEvent>, JsError> {
        let sdk = self.inner.clone();
        let cursor = if cursor.is_null() || cursor.is_undefined() {
            None
        } else {
            let id_js = Reflect::get(&cursor, &JsValue::from_str("id"))
                .map_err(|e| JsError::new(&format!("read cursor.id: {e:?}")))?;
            let id = id_js
                .as_string()
                .ok_or_else(|| JsError::new("cursor.id must be a string"))?;
            let after_js = Reflect::get(&cursor, &JsValue::from_str("after"))
                .map_err(|e| JsError::new(&format!("read cursor.after: {e:?}")))?;
            let after: js_sys::Date = after_js
                .dyn_into()
                .map_err(|_| JsError::new("cursor.after must be a Date"))?;
            Some(sia_storage::ObjectsCursor {
                id: Hash256::from_str(&id).map_err(to_js_err)?,
                after: ms_to_chrono(after.get_time())?,
            })
        };
        let events =
            run_local(async move { sdk.object_events(cursor, Some(limit as usize)).await })
                .await
                .map_err(to_js_err)?;
        Ok(events.into_iter().map(ObjectEvent::from).collect())
    }

    /// Retrieves a pinned slab from the indexer by its hex ID.
    #[wasm_bindgen(unchecked_return_type = "PinnedSlab")]
    pub async fn slab(&self, slab_id: &str) -> Result<JsValue, JsError> {
        let sdk = self.inner.clone();
        let id = Hash256::from_str(slab_id).map_err(to_js_err)?;
        let slab = run_local(async move { sdk.slab(&id).await })
            .await
            .map_err(to_js_err)?;
        types::to_js(&slab)
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
    #[wasm_bindgen(unchecked_return_type = "ReadableStream")]
    pub fn download(
        &self,
        object: &PinnedObject,
        options: Option<JsValue>,
    ) -> Result<web_sys::ReadableStream, JsError> {
        const CHUNK_SIZE: usize = 1 << 18; // matches sia_storage chunk size for optimal performance
        let obj = object.0.clone();
        let opts = options.map(download_options_from_js).unwrap_or_default();
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
    /// const obj = await sdk.upload(new PinnedObject(), file.stream());
    /// await sdk.pinObject(obj);
    /// ```
    pub async fn upload(
        &self,
        object: PinnedObject,
        source: web_sys::ReadableStream,
        options: Option<JsValue>,
    ) -> Result<PinnedObject, JsError> {
        let sdk = self.inner.clone();
        let opts = match options {
            Some(v) => upload_options_from_js(v)?,
            None => Default::default(),
        };
        let obj = object.0;
        let reader = js_stream_reader(source).compat();
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
    pub fn upload_packed(&self, options: Option<JsValue>) -> Result<PackedUpload, JsError> {
        let opts = options
            .map(packed_upload_options_from_js)
            .unwrap_or_default();
        Ok(PackedUpload::new(
            self.inner.upload_packed(opts).map_err(to_js_err)?,
        ))
    }

    /// Generates a signed share URL for an object. Anyone with the URL can
    /// download and decrypt the object until `validUntil`.
    #[wasm_bindgen(js_name = "objectShareUrl")]
    pub fn object_share_url(
        &self,
        object: &PinnedObject,
        valid_until: js_sys::Date,
    ) -> Result<String, JsError> {
        let valid_until = ms_to_chrono(valid_until.get_time())?;
        let url = self
            .inner
            .object_share_url(&object.0, valid_until)
            .map_err(to_js_err)?;
        Ok(url.to_string())
    }

    /// Resolves a share URL (sia://...) and returns the shared object.
    /// The encryption key is extracted from the URL fragment (never sent
    /// to the indexer).
    #[wasm_bindgen(js_name = "objectFromShareUrl")]
    pub async fn object_from_share_url(&self, share_url: &str) -> Result<PinnedObject, JsError> {
        let sdk = self.inner.clone();
        let url = share_url.to_string();
        let obj = run_local(async move { sdk.object_from_share_url(url).await })
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

#[wasm_bindgen(typescript_custom_section)]
const _: &str = r#"
interface Sdk {
    download(object: PinnedObject, options?: DownloadOptions): ReadableStream;
    upload(object: PinnedObject, source: ReadableStream, options?: UploadOptions): Promise<PinnedObject>;
    uploadPacked(options?: PackedUploadOptions): PackedUpload;
}
"#;
