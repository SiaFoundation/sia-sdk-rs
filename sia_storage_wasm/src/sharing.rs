use std::str::FromStr;

use sia_core::types::Hash256;
use sia_storage::{
    KeyResponse as StorageKeyResponse, Sdk as StorageSdk, SharedSdk as StorageSharedSdk,
    SharingKey as StorageSharingKey,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;
use crate::object::PinnedObject;
use crate::types::{self, KeyStats, download_options_from_js};

/// A sharing key, granting read-only access to the objects attached to it.
///
/// Carries the SDK it was created from, so operations read as methods on the
/// key rather than taking one back as an argument.
#[wasm_bindgen]
pub struct SharingKey {
    inner: StorageSharingKey,
    sdk: StorageSdk,
}

impl SharingKey {
    pub(crate) fn new(inner: StorageSharingKey, sdk: StorageSdk) -> Self {
        Self { inner, sdk }
    }

    pub(crate) fn key(&self) -> &StorageSharingKey {
        &self.inner
    }
}

#[wasm_bindgen]
impl SharingKey {
    /// The key's public half, which identifies it.
    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> String {
        self.inner.public_key.to_string()
    }

    /// Returns the seed a recipient needs to read the key's objects, as hex.
    ///
    /// It is the whole credential. Pair it with the indexer's url in
    /// `SharedSdk.connect`.
    pub fn seed(&self) -> Result<String, JsError> {
        let seed = self.inner.seed(&self.sdk).map_err(to_js_err)?;
        Ok(hex::encode(seed))
    }

    /// Attaches an object, re-sealing its encryption keys under the sharing key
    /// so recipients can decrypt it.
    ///
    /// Attaching an object that is already attached replaces its re-sealed
    /// keys, so a failed call can be retried with the same object.
    #[wasm_bindgen(js_name = "addObject")]
    pub async fn add_object(&self, object: &PinnedObject) -> Result<(), JsError> {
        self.inner
            .add_object(&self.sdk, &object.0)
            .await
            .map_err(to_js_err)
    }

    /// Lists and decrypts the objects attached to the key.
    pub async fn objects(&self, offset: u32, limit: u32) -> Result<Vec<PinnedObject>, JsError> {
        let objects = self
            .inner
            .objects(&self.sdk, offset as u64, limit as u64)
            .await
            .map_err(to_js_err)?;
        Ok(objects.into_iter().map(PinnedObject).collect())
    }

    /// Detaches an object from the key, leaving it and its other attachments in
    /// place.
    #[wasm_bindgen(js_name = "deleteObject")]
    pub async fn delete_object(&self, id: String) -> Result<(), JsError> {
        let id = Hash256::from_str(&id).map_err(to_js_err)?;
        self.inner
            .delete_object(&self.sdk, &id)
            .await
            .map_err(to_js_err)
    }

    /// Deletes the key along with all of its attachments, revoking recipients'
    /// access to the indexer.
    ///
    /// Account tokens already issued stay valid until they expire, so a
    /// download already in flight can keep reading from hosts for up to five
    /// more minutes.
    pub async fn delete(&self) -> Result<(), JsError> {
        self.inner.delete(&self.sdk).await.map_err(to_js_err)
    }
}

/// The indexer's record for a sharing key, including how many objects it grants
/// access to and how much space they use. The counts are a snapshot, not a live
/// view.
#[wasm_bindgen]
pub struct KeyResponse {
    inner: StorageKeyResponse,
    sdk: StorageSdk,
}

impl KeyResponse {
    pub(crate) fn new(inner: StorageKeyResponse, sdk: StorageSdk) -> Self {
        Self { inner, sdk }
    }
}

#[wasm_bindgen]
impl KeyResponse {
    /// The key this record describes, ready to operate on.
    #[wasm_bindgen(getter)]
    pub fn key(&self) -> SharingKey {
        SharingKey::new(self.inner.key, self.sdk.clone())
    }

    /// The account that owns the key.
    #[wasm_bindgen(getter)]
    pub fn account(&self) -> String {
        self.inner.account.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn description(&self) -> String {
        self.inner.description.clone()
    }

    #[wasm_bindgen(getter, js_name = "objectCount")]
    pub fn object_count(&self) -> f64 {
        self.inner.stats.object_count as f64
    }

    #[wasm_bindgen(getter, js_name = "objectSize")]
    pub fn object_size(&self) -> f64 {
        self.inner.stats.object_size as f64
    }

    #[wasm_bindgen(getter, js_name = "pinnedData")]
    pub fn pinned_data(&self) -> f64 {
        self.inner.stats.pinned_data as f64
    }

    #[wasm_bindgen(getter, js_name = "pinnedSize")]
    pub fn pinned_size(&self) -> f64 {
        self.inner.stats.pinned_size as f64
    }

    /// When the key expires, or `undefined` if it never does.
    #[wasm_bindgen(getter, js_name = "expiresAt")]
    pub fn expires_at(&self) -> Option<js_sys::Date> {
        self.inner.stats.expires_at.map(types::to_js_date)
    }

    #[wasm_bindgen(getter, js_name = "createdAt")]
    pub fn created_at(&self) -> js_sys::Date {
        types::to_js_date(self.inner.stats.created_at)
    }

    #[wasm_bindgen(getter, js_name = "updatedAt")]
    pub fn updated_at(&self) -> js_sys::Date {
        types::to_js_date(self.inner.stats.updated_at)
    }
}

/// A read-only SDK for the objects a sharing key grants access to.
///
/// Unlike `Sdk`, it authenticates with a sharing key rather than an app key and
/// cannot upload, pin, or delete. Downloads are paid for by the key's owner.
#[wasm_bindgen]
pub struct SharedSdk {
    inner: StorageSharedSdk,
}

#[wasm_bindgen]
impl SharedSdk {
    /// Connects to `indexerUrl` as the recipient of the sharing key derived
    /// from `seed`, which is the hex string the key's owner handed out.
    pub async fn connect(indexer_url: String, seed: String) -> Result<SharedSdk, JsError> {
        let bytes = hex::decode(seed.trim()).map_err(to_js_err)?;
        let seed: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            JsError::new(&format!("seed must be 32 bytes, got {}", v.len()))
        })?;
        let inner = StorageSharedSdk::connect(indexer_url, seed)
            .await
            .map_err(to_js_err)?;
        Ok(Self { inner })
    }

    /// Fetches the sharing key's stats from the indexer.
    pub async fn stats(&self) -> Result<KeyStats, JsError> {
        Ok(self.inner.stats().await.map_err(to_js_err)?.into())
    }

    /// Fetches and decrypts one object the key grants access to.
    pub async fn object(&self, id: String) -> Result<PinnedObject, JsError> {
        let id = Hash256::from_str(&id).map_err(to_js_err)?;
        let object = self.inner.object(&id).await.map_err(to_js_err)?;
        Ok(PinnedObject(object))
    }

    /// Lists and decrypts a page of the objects the key grants access to.
    pub async fn objects(&self, offset: u32, limit: u32) -> Result<Vec<PinnedObject>, JsError> {
        let objects = self
            .inner
            .objects(offset as u64, limit as u64)
            .await
            .map_err(to_js_err)?;
        Ok(objects.into_iter().map(PinnedObject).collect())
    }

    /// Streams a shared object's data.
    pub fn download(
        &self,
        object: &PinnedObject,
        options: Option<JsValue>,
    ) -> Result<web_sys::ReadableStream, JsError> {
        const CHUNK_SIZE: usize = 1 << 18;
        let opts = options.map(download_options_from_js).unwrap_or_default();
        let download = self.inner.download(&object.0, opts).map_err(to_js_err)?;
        Ok(wasm_streams::ReadableStream::from_async_read(download.compat(), CHUNK_SIZE).into_raw())
    }
}
