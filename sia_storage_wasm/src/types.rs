use sia_core::types::v2::Protocol;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::helpers::to_js_err;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "(shardsUploaded: number) => void")]
    pub type OnShardProgressCallback;
}

/// Options for uploading data.
#[wasm_bindgen]
pub struct UploadOptions {
    pub(crate) data_shards: u8,
    pub(crate) parity_shards: u8,
    pub(crate) max_inflight: usize,
    pub(crate) on_progress: Option<js_sys::Function>,
}

#[wasm_bindgen]
impl UploadOptions {
    /// Creates upload options with the given parameters.
    /// Defaults: data_shards=10, parity_shards=20, max_inflight=15.
    #[wasm_bindgen(constructor)]
    pub fn new(
        data_shards: Option<u8>,
        parity_shards: Option<u8>,
        max_inflight: Option<u32>,
        on_progress: Option<OnShardProgressCallback>,
    ) -> Self {
        Self {
            data_shards: data_shards.unwrap_or(10),
            parity_shards: parity_shards.unwrap_or(20),
            max_inflight: max_inflight.unwrap_or(15) as usize,
            on_progress: on_progress.map(|cb| cb.unchecked_into()),
        }
    }
}

impl UploadOptions {
    pub(crate) fn to_inner(&self) -> sia_storage::UploadOptions {
        let defaults = sia_storage::UploadOptions::default();
        sia_storage::UploadOptions {
            data_shards: self.data_shards,
            parity_shards: self.parity_shards,
            max_inflight: self.max_inflight,
            ..defaults
        }
    }
}

/// Options for downloading data.
#[wasm_bindgen]
pub struct DownloadOptions {
    pub(crate) max_inflight: usize,
    pub(crate) offset: u64,
    pub(crate) length: Option<u64>,
}

#[wasm_bindgen]
impl DownloadOptions {
    /// Creates download options with the given parameters.
    /// Defaults: max_inflight=16, offset=0, length=None (full object).
    #[wasm_bindgen(constructor)]
    pub fn new(
        max_inflight: Option<u32>,
        offset: Option<f64>,
        length: Option<f64>,
    ) -> Result<DownloadOptions, JsValue> {
        if let Some(o) = offset
            && o < 0.0
        {
            return Err(JsValue::from_str("offset must be non-negative"));
        }
        if let Some(l) = length
            && l < 0.0
        {
            return Err(JsValue::from_str("length must be non-negative"));
        }
        Ok(Self {
            max_inflight: max_inflight.unwrap_or(16) as usize,
            offset: offset.unwrap_or(0.0) as u64,
            length: length.map(|l| l as u64),
        })
    }
}

impl DownloadOptions {
    pub(crate) fn to_inner(&self) -> sia_storage::DownloadOptions {
        sia_storage::DownloadOptions {
            max_inflight: self.max_inflight,
            offset: self.offset,
            length: self.length,
        }
    }
}

/// Query parameters for filtering hosts. Always filters for QUIC-only hosts
/// since WASM uses WebTransport exclusively.
#[wasm_bindgen]
pub struct HostQuery {
    pub(crate) country: Option<String>,
    pub(crate) limit: Option<u64>,
    pub(crate) offset: Option<u64>,
}

#[wasm_bindgen]
impl HostQuery {
    /// Creates a host query. All parameters are optional.
    #[wasm_bindgen(constructor)]
    pub fn new(country: Option<String>, limit: Option<u32>, offset: Option<u32>) -> Self {
        Self {
            country,
            limit: limit.map(|l| l as u64),
            offset: offset.map(|o| o as u64),
        }
    }
}

impl HostQuery {
    pub(crate) fn to_inner(&self) -> sia_storage::HostQuery {
        sia_storage::HostQuery {
            protocol: Some(Protocol::QUIC),
            country: self.country.clone(),
            limit: self.limit,
            offset: self.offset,
            ..Default::default()
        }
    }
}

/// Account information returned by `Sdk.account()`.
#[wasm_bindgen(getter_with_clone)]
pub struct Account {
    #[wasm_bindgen(js_name = "accountKey")]
    pub account_key: String,
    #[wasm_bindgen(js_name = "maxPinnedData")]
    pub max_pinned_data: f64,
    #[wasm_bindgen(js_name = "remainingStorage")]
    pub remaining_storage: f64,
    #[wasm_bindgen(js_name = "pinnedData")]
    pub pinned_data: f64,
    #[wasm_bindgen(js_name = "pinnedSize")]
    pub pinned_size: f64,
    pub ready: bool,
    #[wasm_bindgen(js_name = "appName")]
    pub app_name: String,
    #[wasm_bindgen(js_name = "appDescription")]
    pub app_description: String,
}

/// Host information returned by `Sdk.hosts()`.
#[wasm_bindgen(getter_with_clone)]
pub struct Host {
    #[wasm_bindgen(js_name = "publicKey")]
    pub public_key: String,
    #[wasm_bindgen(js_name = "countryCode")]
    pub country_code: String,
    #[wasm_bindgen(js_name = "goodForUpload")]
    pub good_for_upload: bool,
}

/// A 32-byte encryption key used for slab-level encryption.
#[wasm_bindgen]
pub struct EncryptionKey(pub(crate) sia_storage::EncryptionKey);

#[wasm_bindgen]
impl EncryptionKey {
    /// Returns the key as a hex-encoded string (64 chars).
    #[wasm_bindgen(js_name = "toHex")]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_ref())
    }

    /// Returns the raw 32 bytes as a Uint8Array.
    pub fn bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }

    /// Parses an encryption key from a hex string (64 chars).
    #[wasm_bindgen(js_name = "fromHex")]
    pub fn from_hex(hex_str: &str) -> Result<EncryptionKey, JsValue> {
        let bytes = hex::decode(hex_str).map_err(to_js_err)?;
        if bytes.len() != 32 {
            return Err(JsValue::from_str("encryption key must be 32 bytes of hex"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(EncryptionKey(sia_storage::EncryptionKey::from(arr)))
    }
}

/// A sector stored on a specific host.
#[wasm_bindgen(getter_with_clone)]
pub struct Sector {
    pub root: String,
    #[wasm_bindgen(js_name = "hostKey")]
    pub host_key: String,
}

/// A slab — an erasure-coded segment of a file. Contains up to 30 sectors
/// (10 data + 20 parity by default), each stored on a different host.
#[wasm_bindgen]
pub struct Slab {
    inner: sia_storage::Slab,
}

#[wasm_bindgen]
impl Slab {
    /// Returns the slab encryption key.
    #[wasm_bindgen(js_name = "encryptionKey")]
    pub fn encryption_key(&self) -> EncryptionKey {
        EncryptionKey(self.inner.encryption_key.clone())
    }

    /// Minimum number of sectors needed to reconstruct the data.
    #[wasm_bindgen(js_name = "minShards")]
    pub fn min_shards(&self) -> u8 {
        self.inner.min_shards
    }

    /// Byte offset within the object.
    pub fn offset(&self) -> u32 {
        self.inner.offset
    }

    /// Data length in bytes.
    pub fn length(&self) -> u32 {
        self.inner.length
    }

    /// Returns the sectors in this slab.
    pub fn sectors(&self) -> Vec<Sector> {
        self.inner
            .sectors
            .iter()
            .map(|s| Sector {
                root: s.root.to_string(),
                host_key: s.host_key.to_string(),
            })
            .collect()
    }
}

impl From<&sia_storage::Slab> for Slab {
    fn from(s: &sia_storage::Slab) -> Self {
        Self { inner: s.clone() }
    }
}

/// Object event returned by `Sdk.objectEvents()`.
#[wasm_bindgen(getter_with_clone)]
pub struct ObjectEvent {
    pub id: String,
    pub deleted: bool,
    #[wasm_bindgen(js_name = "updatedAt")]
    pub updated_at: f64,
    /// Size in bytes, or -1 if the object was deleted.
    pub size: f64,
}
