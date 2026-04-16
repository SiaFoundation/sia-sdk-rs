use wasm_bindgen::prelude::*;

use crate::app_key::AppKey;
use crate::helpers::to_js_err;
use crate::sealed::SealedObject;
use crate::types;

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

    /// Returns the creation time.
    #[wasm_bindgen(js_name = "createdAt")]
    pub fn created_at(&self) -> js_sys::Date {
        js_sys::Date::new(&JsValue::from(self.0.created_at().timestamp_millis() as f64))
    }

    /// Returns the last updated time.
    #[wasm_bindgen(js_name = "updatedAt")]
    pub fn updated_at(&self) -> js_sys::Date {
        js_sys::Date::new(&JsValue::from(self.0.updated_at().timestamp_millis() as f64))
    }

    /// Returns the slabs that make up the object.
    #[wasm_bindgen(unchecked_return_type = "Slab[]")]
    pub fn slabs(&self) -> Result<JsValue, JsError> {
        types::to_js(self.0.slabs())
    }

    /// Seals the object for offline storage.
    pub fn seal(&self, app_key: &AppKey) -> SealedObject {
        SealedObject(self.0.seal(&app_key.0))
    }

    /// Opens a previously sealed object.
    pub fn open(app_key: &AppKey, sealed_obj: SealedObject) -> Result<PinnedObject, JsError> {
        let obj = sealed_obj.0.open(&app_key.0).map_err(to_js_err)?;
        Ok(PinnedObject(obj))
    }
}
