use sia_core::types::v2::Protocol;
use wasm_bindgen::prelude::*;

/// Options for uploading data.
#[wasm_bindgen]
pub struct UploadOptions {
    pub(crate) data_shards: u8,
    pub(crate) parity_shards: u8,
    pub(crate) max_inflight: usize,
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
    ) -> Self {
        Self {
            data_shards: data_shards.unwrap_or(10),
            parity_shards: parity_shards.unwrap_or(20),
            max_inflight: max_inflight.unwrap_or(15) as usize,
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
    pub fn new(max_inflight: Option<u32>, offset: Option<f64>, length: Option<f64>) -> Self {
        Self {
            max_inflight: max_inflight.unwrap_or(16) as usize,
            offset: offset.unwrap_or(0.0) as u64,
            length: length.map(|l| l as u64),
        }
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
