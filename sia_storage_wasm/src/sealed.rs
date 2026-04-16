use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;
use crate::types::Slab;

/// A sealed object for offline storage or migration between indexers.
/// Contains encrypted keys, slab metadata, and signatures.
/// Can be serialized to JSON with `toJson()` and restored with `fromJson()`.
#[wasm_bindgen]
pub struct SealedObject {
    pub(crate) inner: sia_storage::SealedObject,
}

#[wasm_bindgen]
impl SealedObject {
    /// The encrypted data key (Uint8Array).
    #[wasm_bindgen(js_name = "encryptedDataKey")]
    pub fn encrypted_data_key(&self) -> Vec<u8> {
        self.inner.encrypted_data_key.clone()
    }

    /// The encrypted metadata key (Uint8Array).
    #[wasm_bindgen(js_name = "encryptedMetadataKey")]
    pub fn encrypted_metadata_key(&self) -> Vec<u8> {
        self.inner.encrypted_metadata_key.clone()
    }

    /// The encrypted metadata (Uint8Array).
    #[wasm_bindgen(js_name = "encryptedMetadata")]
    pub fn encrypted_metadata(&self) -> Vec<u8> {
        self.inner.encrypted_metadata.clone()
    }

    /// The data signature (64 bytes).
    #[wasm_bindgen(js_name = "dataSignature")]
    pub fn data_signature(&self) -> Vec<u8> {
        self.inner.data_signature.as_ref().to_vec()
    }

    /// The metadata signature (64 bytes).
    #[wasm_bindgen(js_name = "metadataSignature")]
    pub fn metadata_signature(&self) -> Vec<u8> {
        self.inner.metadata_signature.as_ref().to_vec()
    }

    /// The slabs that make up the sealed object.
    pub fn slabs(&self) -> Vec<Slab> {
        self.inner.slabs.iter().map(Slab::from).collect()
    }

    /// Creation time as a unix timestamp (seconds).
    #[wasm_bindgen(js_name = "createdAt")]
    pub fn created_at(&self) -> f64 {
        self.inner.created_at.timestamp() as f64
    }

    /// Last updated time as a unix timestamp (seconds).
    #[wasm_bindgen(js_name = "updatedAt")]
    pub fn updated_at(&self) -> f64 {
        self.inner.updated_at.timestamp() as f64
    }

    /// Serializes the sealed object to a JSON string for storage or transfer.
    #[wasm_bindgen(js_name = "toJson")]
    pub fn to_json(&self) -> Result<String, JsError> {
        serde_json::to_string(&self.inner).map_err(to_js_err)
    }

    /// Restores a sealed object from a JSON string.
    #[wasm_bindgen(js_name = "fromJson")]
    pub fn from_json(json: &str) -> Result<SealedObject, JsError> {
        let inner: sia_storage::SealedObject = serde_json::from_str(json).map_err(to_js_err)?;
        Ok(SealedObject { inner })
    }
}
