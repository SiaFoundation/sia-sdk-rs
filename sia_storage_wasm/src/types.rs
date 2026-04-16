use sia_core::types::v2::Protocol;
use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;
use crate::object::PinnedObject;

/// Application metadata deserialized from a plain JS object.
#[derive(serde::Deserialize, tsify::Tsify)]
#[tsify(from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct AppMetadata {
    pub app_id: String,
    pub name: String,
    pub description: String,
    pub service_url: String,
    pub logo_url: Option<String>,
    pub callback_url: Option<String>,
}

/// Options for uploading data. Deserialized from a plain JS object.
/// The `onProgress` callback is extracted separately since JS functions
/// can't pass through serde.
pub struct UploadOptions {
    pub data_shards: Option<u8>,
    pub parity_shards: Option<u8>,
    pub max_inflight: Option<usize>,
    pub on_progress: Option<js_sys::Function>,
}

// Manually generate the TS interface since tsify can't handle the mixed
// serde + JS function field.
#[wasm_bindgen(typescript_custom_section)]
const _: &str = r#"
export interface UploadOptions {
    dataShards?: number;
    parityShards?: number;
    maxInflight?: number;
    onProgress?: (uploaded: number, encodedSize: number) => void;
}
"#;

impl UploadOptions {
    /// Deserializes from a JsValue, extracting the onProgress callback separately.
    pub fn from_js(val: JsValue) -> Result<Self, JsError> {
        use wasm_bindgen::JsCast;

        // Extract the callback before deserializing the rest
        let on_progress = js_sys::Reflect::get(&val, &"onProgress".into())
            .ok()
            .filter(|v| v.is_function())
            .map(|v| v.unchecked_into::<js_sys::Function>());

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Opts {
            data_shards: Option<u8>,
            parity_shards: Option<u8>,
            max_inflight: Option<usize>,
        }

        let opts: Opts = serde_wasm_bindgen::from_value(val).map_err(to_js_err)?;
        Ok(Self {
            data_shards: opts.data_shards,
            parity_shards: opts.parity_shards,
            max_inflight: opts.max_inflight,
            on_progress,
        })
    }
}

impl From<UploadOptions> for sia_storage::UploadOptions {
    fn from(opts: UploadOptions) -> Self {
        let mut merged = sia_storage::UploadOptions::default();
        if let Some(v) = opts.data_shards {
            merged.data_shards = v;
        }
        if let Some(v) = opts.parity_shards {
            merged.parity_shards = v;
        }
        if let Some(v) = opts.max_inflight {
            merged.max_inflight = v;
        }
        merged.shard_uploaded = opts.on_progress.map(|cb| {
            let total_shards = merged.data_shards as u64 + merged.parity_shards as u64;
            let slab_size = total_shards * sia_core::rhp4::SECTOR_SIZE as u64;
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            tokio::task::spawn_local(async move {
                let mut sectors: u64 = 0;
                while rx.recv().await.is_some() {
                    sectors += 1;
                    let uploaded = sectors * sia_core::rhp4::SECTOR_SIZE as u64;
                    let encoded = sectors.div_ceil(total_shards) * slab_size;
                    let _ = cb.call2(
                        &wasm_bindgen::JsValue::NULL,
                        &wasm_bindgen::JsValue::from(uploaded as f64),
                        &wasm_bindgen::JsValue::from(encoded as f64),
                    );
                }
            });
            tx
        });
        merged
    }
}

/// Options for downloading data.
#[derive(serde::Deserialize, tsify::Tsify)]
#[tsify(from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct DownloadOptions {
    pub max_inflight: Option<usize>,
    pub offset: Option<f64>,
    pub length: Option<f64>,
}

impl From<DownloadOptions> for sia_storage::DownloadOptions {
    fn from(opts: DownloadOptions) -> Self {
        let mut merged = sia_storage::DownloadOptions::default();
        if let Some(v) = opts.max_inflight {
            merged.max_inflight = v;
        }
        if let Some(v) = opts.offset {
            merged.offset = v as u64;
        }
        if let Some(v) = opts.length {
            merged.length = Some(v as u64);
        }
        merged
    }
}

/// Query parameters for filtering hosts.
#[derive(serde::Deserialize, tsify::Tsify)]
#[tsify(from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct HostQuery {
    pub country: Option<String>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

impl From<HostQuery> for sia_storage::HostQuery {
    fn from(q: HostQuery) -> Self {
        Self {
            protocol: Some(Protocol::QUIC),
            country: q.country,
            limit: q.limit,
            offset: q.offset,
            ..Default::default()
        }
    }
}

/// Converts milliseconds since epoch to a chrono::DateTime<Utc>.
pub(crate) fn ms_to_chrono(ms: f64) -> Result<chrono::DateTime<chrono::Utc>, JsError> {
    let secs = (ms / 1000.0) as i64;
    let nanos = ((ms % 1000.0) * 1_000_000.0) as u32;
    chrono::DateTime::from_timestamp(secs, nanos).ok_or_else(|| JsError::new("invalid timestamp"))
}

/// A cursor for paginating through object events.
#[derive(serde::Deserialize, tsify::Tsify)]
#[tsify(from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct ObjectsCursor {
    pub id: String,
    #[tsify(type = "Date")]
    #[serde(with = "serde_wasm_bindgen::preserve")]
    pub after: js_sys::Date,
}

/// An object event from the indexer.
#[wasm_bindgen]
pub struct ObjectEvent {
    id: String,
    deleted: bool,
    updated_at: chrono::DateTime<chrono::Utc>,
    object: Option<PinnedObject>,
}

#[wasm_bindgen]
impl ObjectEvent {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn deleted(&self) -> bool {
        self.deleted
    }

    /// Returns the time the event occurred.
    #[wasm_bindgen(getter, js_name = "updatedAt")]
    pub fn updated_at(&self) -> js_sys::Date {
        js_sys::Date::new(&JsValue::from(self.updated_at.timestamp_millis() as f64))
    }

    /// Returns the object associated with this event, if it exists.
    #[wasm_bindgen(getter)]
    pub fn object(&self) -> Option<PinnedObject> {
        self.object.as_ref().map(|o| PinnedObject(o.0.clone()))
    }
}

impl From<sia_storage::ObjectEvent> for ObjectEvent {
    fn from(e: sia_storage::ObjectEvent) -> Self {
        Self {
            id: e.id.to_string(),
            deleted: e.deleted,
            updated_at: e.updated_at,
            object: e.object.map(PinnedObject),
        }
    }
}

/// Manual TypeScript declarations for core types that can't use tsify
/// (defined in sia_storage, not this crate).
#[wasm_bindgen(typescript_custom_section)]
const _: &str = r#"
export interface Sector {
    root: string;
    hostKey: string;
}

export interface Slab {
    encryptionKey: string;
    minShards: number;
    offset: number;
    length: number;
    sectors: Sector[];
}

export interface PinnedSlab {
    id: string;
    encryptionKey: string;
    minShards: number;
    sectors: Sector[];
}

export interface Account {
    accountKey: string;
    maxPinnedData: number;
    remainingStorage: number;
    pinnedData: number;
    pinnedSize: number;
    ready: boolean;
    app: {
        id: string;
        name: string;
        description: string;
        serviceUrl?: string;
        logoUrl?: string;
    };
    lastUsed: string;
}

export interface Host {
    publicKey: string;
    addresses: { protocol: string; address: string }[];
    countryCode: string;
    latitude: number;
    longitude: number;
    goodForUpload: boolean;
}
"#;

/// Serializes a value to a JsValue via serde_wasm_bindgen.
pub(crate) fn to_js<T: serde::Serialize + ?Sized>(val: &T) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(val).map_err(to_js_err)
}
