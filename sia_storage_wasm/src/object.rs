use sia_storage::SealedObject;
use wasm_bindgen::prelude::*;

use crate::app_key::AppKey;
use crate::helpers::{Slab, to_js_err, to_js_value};

/// An object stored on the Sia network. JS holds this as an opaque handle
/// and passes it back to Rust for operations like pin, download, share, and
/// metadata updates. The internal state (encryption keys, slab data) cannot
/// be serialized to JS.
#[wasm_bindgen]
pub struct PinnedObject(pub(crate) sia_storage::Object);

#[wasm_bindgen]
impl PinnedObject {
    /// Returns the object's ID as a hex string.
    pub fn id(&self) -> String {
        self.0.id().to_string()
    }

    /// Returns the total size of the object in bytes.
    pub fn size(&self) -> u64 {
        self.0.size()
    }

    /// Returns the encoded (on-network) size after erasure coding.
    #[wasm_bindgen(js_name = "encodedSize")]
    pub fn encoded_size(&self) -> u64 {
        self.0.encoded_size()
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
    /// The returned JS object contains encrypted keys and slab metadata —
    /// it can be JSON.stringify'd and stored or transferred to another indexer.
    pub fn seal(&self, app_key: &AppKey) -> Result<JsValue, JsValue> {
        let sealed = self.0.seal(&app_key.0);
        to_js_value(&sealed)
    }

    /// Opens a previously sealed object. Pass the JS object returned by
    /// seal() (or parsed from JSON). Returns a PinnedObject handle that
    /// can be pinned to this or another indexer.
    pub fn open(app_key: &AppKey, sealed: JsValue) -> Result<PinnedObject, JsValue> {
        let sealed: SealedObject =
            serde_wasm_bindgen::from_value(sealed).map_err(to_js_err)?;
        let obj = sealed.open(&app_key.0).map_err(to_js_err)?;
        Ok(PinnedObject(obj))
    }
}
