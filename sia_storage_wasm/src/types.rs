use std::str::FromStr;

use js_sys::Reflect;
use sia_core::types::Hash256;
use sia_core::types::v2::Protocol;
use tsify::Ts;
use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;
use crate::object::{ObjectSummary, PinnedObject};

/// Progress information about a successfully uploaded or downloaded shard.
#[derive(serde::Serialize, tsify::Tsify)]
#[serde(rename_all = "camelCase")]
pub struct ShardProgress {
    pub host_key: String,
    pub shard_size: usize,
    pub shard_index: usize,
    pub slab_index: usize,
    /// Elapsed time in milliseconds since the start of the shard upload or download.
    pub elapsed_ms: f64,
}

impl From<sia_storage::ShardProgress> for ShardProgress {
    fn from(p: sia_storage::ShardProgress) -> Self {
        Self {
            host_key: p.host_key.to_string(),
            shard_size: p.shard_size,
            shard_index: p.shard_index,
            slab_index: p.slab_index,
            elapsed_ms: p.elapsed.as_millis() as f64,
        }
    }
}

/// Application info registered with the indexer.
#[derive(serde::Serialize, tsify::Tsify)]
#[serde(rename_all = "camelCase")]
pub struct App {
    pub id: String,
    pub name: String,
    pub description: String,
    pub logo_url: Option<String>,
    pub service_url: Option<String>,
}

impl From<sia_storage::App> for App {
    fn from(a: sia_storage::App) -> Self {
        Self {
            id: a.id.to_string(),
            name: a.name,
            description: a.description,
            logo_url: a.logo_url,
            service_url: a.service_url,
        }
    }
}

/// Information about the user's account on the indexer.
#[derive(serde::Serialize, tsify::Tsify)]
#[serde(rename_all = "camelCase")]
#[tsify(large_number_types_as_bigints)]
pub struct Account {
    pub account_key: String,
    /// The pinning limit in bytes. An account with no limit reports 2^63 - 1.
    pub max_pinned_data: u64,
    pub remaining_storage: u64,
    pub pinned_data: u64,
    pub pinned_size: u64,
    pub ready: bool,
    pub app: App,
    #[tsify(type = "Date")]
    #[serde(with = "serde_wasm_bindgen::preserve")]
    pub last_used: js_sys::Date,
}

impl From<sia_storage::Account> for Account {
    fn from(a: sia_storage::Account) -> Self {
        Self {
            account_key: a.account_key.to_string(),
            max_pinned_data: a.max_pinned_data,
            remaining_storage: a.remaining_storage,
            pinned_data: a.pinned_data,
            pinned_size: a.pinned_size,
            ready: a.ready,
            app: a.app.into(),
            last_used: js_sys::Date::new(&JsValue::from(a.last_used.timestamp_millis() as f64)),
        }
    }
}

/// TS interface for `Builder::new`'s `app` parameter. Field names must
/// match the Reflect reads in `helpers::make_app_metadata`.
// dead_code because it exists only for tsify.
#[derive(serde::Serialize, tsify::Tsify)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
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
    maxBufferedSlabs?: number;
    startOffset?: bigint;
    onShardUploaded?: (progress: ShardProgress) => void;
}

export interface PackedUploadOptions {
    dataShards?: number;
    parityShards?: number;
    maxBufferedSlabs?: number;
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

/// Reads a `bigint` as a u64. A number, a negative value or one above
/// 2^64 - 1 is refused rather than rounded or wrapped, which is what
/// wasm-bindgen does with a plain `u64` parameter.
pub(crate) fn u64_from_js(v: JsValue, name: &str) -> Result<u64, JsError> {
    if !v.is_bigint() {
        return Err(JsError::new(&format!("{name} must be a bigint")));
    }
    u64::try_from(v.unchecked_into::<js_sys::BigInt>()).map_err(|_| {
        JsError::new(&format!(
            "{name} must be a non-negative integer that fits in u64"
        ))
    })
}

fn get_bigint_u64(obj: &js_sys::Object, key: &str) -> Result<Option<u64>, JsError> {
    let Ok(v) = js_sys::Reflect::get(obj, &key.into()) else {
        return Ok(None);
    };
    if v.is_undefined() || v.is_null() {
        return Ok(None);
    }
    u64_from_js(v, key).map(Some)
}

fn packed_options_from_obj(obj: &js_sys::Object) -> sia_storage::PackedUploadOptions {
    let mut options = sia_storage::PackedUploadOptions::default();
    if let Some(v) = get_f64(obj, "dataShards") {
        options.data_shards = v as u8;
    }
    if let Some(v) = get_f64(obj, "parityShards") {
        options.parity_shards = v as u8;
    }
    if let Some(v) = get_f64(obj, "maxBufferedSlabs") {
        options.max_buffered_slabs = Some(v as usize);
    }
    if let Some(cb) = get_function(obj, "onShardUploaded") {
        options.shard_uploaded = Some(shard_progress_callback(cb));
    }
    options
}

pub(crate) fn packed_upload_options_from_js(val: JsValue) -> sia_storage::PackedUploadOptions {
    packed_options_from_obj(&js_sys::Object::from(val))
}

pub(crate) fn upload_options_from_js(val: JsValue) -> Result<sia_storage::UploadOptions, JsError> {
    let obj = js_sys::Object::from(val);
    let mut options: sia_storage::UploadOptions = packed_options_from_obj(&obj).into();
    options.start_offset = get_bigint_u64(&obj, "startOffset")?;
    Ok(options)
}

#[wasm_bindgen(typescript_custom_section)]
const _: &str = r#"
export interface DownloadOptions {
    maxBufferedChunks?: number;
    offset?: bigint;
    length?: bigint;
    onShardDownloaded?: (progress: ShardProgress) => void;
}
"#;

pub(crate) fn download_options_from_js(
    val: JsValue,
) -> Result<sia_storage::DownloadOptions, JsError> {
    let obj = js_sys::Object::from(val);
    let mut options = sia_storage::DownloadOptions::default();
    if let Some(v) = get_f64(&obj, "maxBufferedChunks") {
        options.max_buffered_chunks = Some(v as usize);
    }
    if let Some(v) = get_bigint_u64(&obj, "offset")? {
        options.offset = v;
    }
    options.length = get_bigint_u64(&obj, "length")?;
    if let Some(cb) = get_function(&obj, "onShardDownloaded") {
        options.shard_downloaded = Some(shard_progress_callback(cb));
    }
    Ok(options)
}

/// Query parameters for filtering hosts.
#[derive(Default, serde::Deserialize, tsify::Tsify)]
#[serde(rename_all = "camelCase")]
pub struct HostQuery {
    #[tsify(optional)]
    pub location: Option<GeoLocation>,
    #[tsify(optional)]
    pub country: Option<String>,
    #[tsify(optional)]
    pub limit: Option<u64>,
    #[tsify(optional)]
    pub offset: Option<u64>,
}

/// Geographic coordinates used to sort hosts by proximity.
#[derive(serde::Deserialize, tsify::Tsify)]
#[serde(rename_all = "camelCase")]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
}

impl From<HostQuery> for sia_storage::HostQuery {
    fn from(q: HostQuery) -> Self {
        Self {
            protocol: Some(Protocol::QUIC),
            location: q.location.map(|location| sia_storage::GeoLocation {
                latitude: location.latitude,
                longitude: location.longitude,
            }),
            country: q.country,
            limit: q.limit,
            offset: q.offset,
        }
    }
}

/// Converts an optional HostQuery from JS, where a missing query means no
/// filters. The protocol is set by the From impl above in both cases.
pub(crate) fn host_query_from_js(
    query: Option<Ts<HostQuery>>,
) -> Result<sia_storage::HostQuery, JsError> {
    let query = match query {
        Some(q) => q.to_rust()?,
        None => HostQuery::default(),
    };
    Ok(query.into())
}

/// Converts milliseconds since epoch to a chrono::DateTime<Utc>.
pub(crate) fn ms_to_chrono(ms: f64) -> Result<chrono::DateTime<chrono::Utc>, JsError> {
    let secs = (ms / 1000.0) as i64;
    let nanos = ((ms % 1000.0) * 1_000_000.0) as u32;
    chrono::DateTime::from_timestamp(secs, nanos).ok_or_else(|| JsError::new("invalid timestamp"))
}

/// TS interface for the `cursor` parameter of `Sdk::objectEvents` and
/// `Sdk::objectEventSummaries`. Field names must match the Reflect reads in
/// `objects_cursor_from_js`.
// dead_code because it exists only for tsify.
#[derive(serde::Serialize, tsify::Tsify)]
#[allow(dead_code)]
pub struct ObjectsCursor {
    pub id: String,
    #[tsify(type = "Date")]
    pub after: f64,
}

/// Reads an optional `ObjectsCursor` from JS, where null or undefined means
/// the first page.
pub(crate) fn objects_cursor_from_js(
    cursor: JsValue,
) -> Result<Option<sia_storage::ObjectsCursor>, JsError> {
    if cursor.is_null() || cursor.is_undefined() {
        return Ok(None);
    }
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
    Ok(Some(sia_storage::ObjectsCursor {
        id: Hash256::from_str(&id).map_err(to_js_err)?,
        after: ms_to_chrono(after.get_time())?,
    }))
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

/// An object event from the indexer, without the object's slabs.
#[wasm_bindgen]
pub struct ObjectEventSummary {
    id: String,
    deleted: bool,
    updated_at: chrono::DateTime<chrono::Utc>,
    object: Option<ObjectSummary>,
}

#[wasm_bindgen]
impl ObjectEventSummary {
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
    pub fn object(&self) -> Option<ObjectSummary> {
        self.object.as_ref().map(|o| ObjectSummary(o.0.clone()))
    }
}

impl From<sia_storage::ObjectEventSummary> for ObjectEventSummary {
    fn from(e: sia_storage::ObjectEventSummary) -> Self {
        Self {
            id: e.id.to_string(),
            deleted: e.deleted,
            updated_at: e.updated_at,
            object: e.object.map(ObjectSummary),
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
    version: number;
    encryptionKey: string;
    minShards: number;
    offset: number;
    length: number;
    sectors: Sector[];
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

/// What a recipient can see about the sharing key they hold. The counts are a
/// snapshot, not a live view.
#[derive(serde::Serialize, tsify::Tsify)]
#[serde(rename_all = "camelCase")]
#[tsify(large_number_types_as_bigints)]
pub struct KeyStats {
    pub object_count: u64,
    pub object_size: u64,
    pub pinned_data: u64,
    pub pinned_size: u64,
    #[tsify(type = "Date | undefined")]
    #[serde(with = "preserve_optional_date")]
    pub expires_at: Option<js_sys::Date>,
    #[tsify(type = "Date")]
    #[serde(with = "serde_wasm_bindgen::preserve")]
    pub created_at: js_sys::Date,
    #[tsify(type = "Date")]
    #[serde(with = "serde_wasm_bindgen::preserve")]
    pub updated_at: js_sys::Date,
}

impl From<sia_storage::KeyStats> for KeyStats {
    fn from(s: sia_storage::KeyStats) -> Self {
        Self {
            object_count: s.object_count,
            object_size: s.object_size,
            pinned_data: s.pinned_data,
            pinned_size: s.pinned_size,
            expires_at: s.expires_at.map(to_js_date),
            created_at: to_js_date(s.created_at),
            updated_at: to_js_date(s.updated_at),
        }
    }
}

pub(crate) fn to_js_date(t: chrono::DateTime<chrono::Utc>) -> js_sys::Date {
    js_sys::Date::new(&JsValue::from(t.timestamp_millis() as f64))
}

/// `serde_wasm_bindgen::preserve` only accepts `JsCast` values, so an optional
/// `Date` needs the `None` case handled separately. It serializes as
/// `undefined`.
mod preserve_optional_date {
    pub(super) fn serialize<S: serde::Serializer>(
        value: &Option<js_sys::Date>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(date) => serde_wasm_bindgen::preserve::serialize(date, serializer),
            None => serializer.serialize_none(),
        }
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use sia_storage::{PublicKey, Utc};
    use tsify::Tsify;
    use wasm_bindgen_test::wasm_bindgen_test;

    /// indexd reports an account with no limit as 2^63 - 1.
    const NO_LIMIT: u64 = i64::MAX as u64;

    fn bigint(v: &JsValue, key: &str) -> u64 {
        let field = Reflect::get(v, &JsValue::from_str(key)).unwrap();
        assert!(field.is_bigint(), "{key} is not a bigint");
        u64::try_from(field.unchecked_into::<js_sys::BigInt>()).unwrap()
    }

    fn big(n: &str) -> JsValue {
        js_sys::BigInt::new(&JsValue::from_str(n)).unwrap().into()
    }

    /// #404: serde_wasm_bindgen refused a u64 above 2^53, so `account()`
    /// threw for every account with no limit.
    #[wasm_bindgen_test]
    fn account_with_no_limit() {
        let account = sia_storage::Account {
            account_key: PublicKey::new([1; 32]),
            max_pinned_data: NO_LIMIT,
            remaining_storage: NO_LIMIT - 4097,
            pinned_data: 4097,
            pinned_size: 12291,
            ready: true,
            app: sia_storage::App {
                id: Hash256::default(),
                name: "app".into(),
                description: "".into(),
                logo_url: None,
                service_url: None,
            },
            last_used: Utc::now(),
        };
        let v: JsValue = Account::from(account).into_ts().unwrap().into();
        assert_eq!(bigint(&v, "maxPinnedData"), NO_LIMIT);
        assert_eq!(bigint(&v, "remainingStorage"), NO_LIMIT - 4097);
        assert_eq!(bigint(&v, "pinnedData"), 4097);
        assert_eq!(bigint(&v, "pinnedSize"), 12291);
    }

    #[wasm_bindgen_test]
    fn key_stats_keep_every_bit() {
        let stats = sia_storage::KeyStats {
            object_count: u64::MAX,
            object_size: u64::MAX - 1,
            pinned_data: (1 << 53) + 1,
            pinned_size: 1,
            expires_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let v: JsValue = KeyStats::from(stats).into_ts().unwrap().into();
        assert_eq!(bigint(&v, "objectCount"), u64::MAX);
        assert_eq!(bigint(&v, "objectSize"), u64::MAX - 1);
        assert_eq!(bigint(&v, "pinnedData"), (1 << 53) + 1);
        assert_eq!(bigint(&v, "pinnedSize"), 1);
    }

    #[wasm_bindgen_test]
    fn bigint_arguments_are_checked() {
        assert_eq!(
            u64_from_js(big("18446744073709551615"), "n").unwrap(),
            u64::MAX
        );
        assert_eq!(
            u64_from_js(big("9007199254740993"), "n").unwrap(),
            (1 << 53) + 1
        );
        assert!(
            u64_from_js(big("18446744073709551616"), "n").is_err(),
            "2^64 wrapped"
        );
        assert!(u64_from_js(big("-1"), "n").is_err(), "-1 wrapped");
        assert!(
            u64_from_js(JsValue::from(5.0), "n").is_err(),
            "number accepted"
        );
    }

    #[wasm_bindgen_test]
    fn download_range_is_exact() {
        let obj = js_sys::Object::new();
        Reflect::set(&obj, &"offset".into(), &big("9007199254740993")).unwrap();
        Reflect::set(&obj, &"length".into(), &big("18446744073709551615")).unwrap();
        let opts = download_options_from_js(obj.into()).unwrap();
        assert_eq!(opts.offset, (1 << 53) + 1);
        assert_eq!(opts.length, Some(u64::MAX));

        let obj = js_sys::Object::new();
        Reflect::set(&obj, &"offset".into(), &JsValue::from(1.5)).unwrap();
        assert!(
            download_options_from_js(obj.into()).is_err(),
            "number accepted"
        );
    }
}
