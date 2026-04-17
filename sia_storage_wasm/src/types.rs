use sia_core::types::v2::Protocol;
use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;
use crate::object::PinnedObject;

/// Progress information about a successfully uploaded or downloaded shard.
#[derive(serde::Serialize, tsify::Tsify)]
#[tsify(into_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct ShardProgress {
    pub host_key: String,
    pub shard_size: usize,
    pub shard_index: usize,
    pub slab_index: usize,
    /// Elapsed time in milliseconds since the start of the upload or download.
    pub elapsed: f64,
}

impl From<sia_storage::ShardProgress> for ShardProgress {
    fn from(p: sia_storage::ShardProgress) -> Self {
        Self {
            host_key: p.host_key.to_string(),
            shard_size: p.shard_size,
            shard_index: p.shard_index,
            slab_index: p.slab_index,
            elapsed: p.elapsed.as_millis() as f64,
        }
    }
}

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

#[wasm_bindgen(typescript_custom_section)]
const _: &str = r#"
export interface UploadOptions {
    dataShards?: number;
    parityShards?: number;
    maxInflight?: number;
    onShardUploaded?: (progress: ShardProgress) => void;
}
"#;

fn shard_progress_callback(cb: js_sys::Function) -> sia_storage::ShardProgressCallback {
    std::sync::Arc::new(move |p: sia_storage::ShardProgress| {
        let progress: ShardProgress = p.into();
        let js_val = serde_wasm_bindgen::to_value(&progress).unwrap_or(JsValue::UNDEFINED);
        let _ = cb.call1(&JsValue::NULL, &js_val);
    })
}

fn get_f64(obj: &js_sys::Object, key: &str) -> Option<f64> {
    js_sys::Reflect::get(obj, &key.into())
        .ok()
        .and_then(|v| v.as_f64())
}

fn get_function(obj: &js_sys::Object, key: &str) -> Option<js_sys::Function> {
    js_sys::Reflect::get(obj, &key.into())
        .ok()
        .and_then(|v| v.dyn_into::<js_sys::Function>().ok())
}

pub(crate) fn upload_options_from_js(val: JsValue) -> sia_storage::UploadOptions {
    let obj = js_sys::Object::from(val);
    let mut options = sia_storage::UploadOptions::default();
    if let Some(v) = get_f64(&obj, "dataShards") {
        options.data_shards = v as u8;
    }
    if let Some(v) = get_f64(&obj, "parityShards") {
        options.parity_shards = v as u8;
    }
    if let Some(v) = get_f64(&obj, "maxInflight") {
        options.max_inflight = v as usize;
    }
    if let Some(cb) = get_function(&obj, "onShardUploaded") {
        options.shard_uploaded = Some(shard_progress_callback(cb));
    }
    options
}

#[wasm_bindgen(typescript_custom_section)]
const _: &str = r#"
export interface DownloadOptions {
    maxInflight?: number;
    offset?: number;
    length?: number;
    onShardDownloaded?: (progress: ShardProgress) => void;
}
"#;

pub(crate) fn download_options_from_js(val: JsValue) -> sia_storage::DownloadOptions {
    let obj = js_sys::Object::from(val);
    let mut options = sia_storage::DownloadOptions::default();
    if let Some(v) = get_f64(&obj, "maxInflight") {
        options.max_inflight = v as usize;
    }
    if let Some(v) = get_f64(&obj, "offset") {
        options.offset = v as u64;
    }
    if let Some(v) = get_f64(&obj, "length") {
        options.length = Some(v as u64);
    }
    if let Some(cb) = get_function(&obj, "onShardDownloaded") {
        options.shard_downloaded = Some(shard_progress_callback(cb));
    }
    options
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

export interface App {
    id: string
    name: string
    description: string
    serviceUrl?: string
    logoUrl?: string
}

export interface Account {
    accountKey: string;
    maxPinnedData: number;
    remainingStorage: number;
    pinnedData: number;
    pinnedSize: number;
    ready: boolean;
    app: App;
    lastUsed: Date;
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
