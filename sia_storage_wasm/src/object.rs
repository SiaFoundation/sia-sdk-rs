use wasm_bindgen::prelude::*;

use crate::app_key::AppKey;
use crate::helpers::to_js_err;
use crate::sealed::SealedObject;
use crate::types::Slab;

/// An object stored on the Sia network. JS holds this as an opaque handle
/// and passes it back to Rust for operations like pin, download, share, and
/// metadata updates. The internal state (encryption keys, slab data) cannot
/// be serialized to JS.
#[wasm_bindgen]
#[derive(Default)]
pub struct PinnedObject(pub(crate) sia_storage::Object);

#[wasm_bindgen]
impl PinnedObject {
    /// Creates a new empty object.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the object's ID as a hex string.
    pub fn id(&self) -> String {
        self.0.id().to_string()
    }

    /// Returns the total size of the object in bytes.
    pub fn size(&self) -> f64 {
        self.0.size() as f64
    }

    /// Returns the encoded (on-network) size after erasure coding.
    #[wasm_bindgen(js_name = "encodedSize")]
    pub fn encoded_size(&self) -> f64 {
        self.0.encoded_size() as f64
    }

    /// Returns the object's metadata as raw bytes.
    pub fn metadata(&self) -> Vec<u8> {
        self.0.metadata.clone()
    }

    /// Updates the object's metadata.
    #[wasm_bindgen(js_name = "updateMetadata")]
    pub fn update_metadata(&mut self, metadata: Vec<u8>) {
        self.0.metadata = metadata;
    }

    /// Returns the creation time as a unix timestamp (seconds).
    #[wasm_bindgen(js_name = "createdAt")]
    pub fn created_at(&self) -> f64 {
        self.0.created_at().timestamp() as f64
    }

    /// Returns the last updated time as a unix timestamp (seconds).
    #[wasm_bindgen(js_name = "updatedAt")]
    pub fn updated_at(&self) -> f64 {
        self.0.updated_at().timestamp() as f64
    }

    /// Returns the number of slabs in the object.
    #[wasm_bindgen(js_name = "slabCount")]
    pub fn slab_count(&self) -> u32 {
        self.0.slabs().len() as u32
    }

    /// Returns the slabs that make up the object.
    pub fn slabs(&self) -> Vec<Slab> {
        self.0.slabs().iter().map(Slab::from).collect()
    }

    /// Seals the object for offline storage or migration.
    pub fn seal(&self, app_key: &AppKey) -> SealedObject {
        let inner = self.0.seal(&app_key.0);
        SealedObject { inner }
    }

    /// Opens a previously sealed object.
    pub fn open(app_key: &AppKey, sealed: &SealedObject) -> Result<PinnedObject, JsError> {
        let obj = sealed.inner.clone().open(&app_key.0).map_err(to_js_err)?;
        Ok(PinnedObject(obj))
    }
}
