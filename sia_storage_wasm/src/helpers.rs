use serde::Serialize;
use sia_core::types::Hash256;
use sia_storage::{AppMetadata, Object};
use wasm_bindgen::prelude::*;

pub(crate) fn to_js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

pub(crate) fn to_js_value<T: Serialize>(v: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(to_js_err)
}

/// Run an async block with a tokio runtime + LocalSet. wasm_bindgen async
/// exports run on the JS microtask queue with no tokio runtime in scope,
/// but the SDK uses tokio primitives (JoinSet::spawn_local, select!, etc.)
/// that require one.
pub(crate) async fn run_local<F: std::future::Future>(f: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("failed to create tokio runtime");
    let _guard = rt.enter();
    tokio::task::LocalSet::new().run_until(f).await
}

/// Cached leaked strings for app metadata. Set once on first call;
/// reused on subsequent calls so we never leak more than one set of strings.
struct CachedMeta {
    id: Hash256,
    name: &'static str,
    description: &'static str,
    service_url: &'static str,
    logo_url: Option<&'static str>,
    callback_url: Option<&'static str>,
}

// AppMetadata requires &'static str fields, but JS strings are heap-allocated.
// Box::leak promotes them to 'static, but leaks memory on every call.
// This cache ensures the leak happens at most once per app ID — subsequent
// SdkBuilder::new() calls reuse the same 'static references.
// thread_local is used because WASM is single-threaded and RefCell
// cannot be in a regular static (it's not Sync).
thread_local! {
    static CACHED_META: std::cell::RefCell<Option<CachedMeta>> = std::cell::RefCell::new(None);
}

/// Constructs an [`AppMetadata`] from JS-provided strings.
///
/// `AppMetadata` requires `&'static str` fields, but strings from JS are
/// temporary. We use `Box::leak` to promote each string to `'static`
/// references. The leaked strings are cached so this only happens once —
/// subsequent calls with the same app ID reuse the cached references.
pub(crate) fn make_app_metadata(
    id_hex: &str,
    name: &str,
    description: &str,
    service_url: &str,
    logo_url: Option<String>,
    callback_url: Option<String>,
) -> Result<AppMetadata, JsValue> {
    let id_bytes = hex::decode(id_hex).map_err(to_js_err)?;
    if id_bytes.len() != 32 {
        return Err(JsValue::from_str("app ID must be 32 bytes (64 hex chars)"));
    }
    let app_id = Hash256::from(
        <[u8; 32]>::try_from(id_bytes).expect("length validated as 32 above"),
    );

    CACHED_META.with(|cell| {
        let mut cache = cell.borrow_mut();

        // Return cached metadata if the app ID matches
        if let Some(ref c) = *cache {
            if c.id == app_id {
                return Ok(AppMetadata {
                    id: c.id,
                    name: c.name,
                    description: c.description,
                    service_url: c.service_url,
                    logo_url: c.logo_url,
                    callback_url: c.callback_url,
                });
            }
        }

        // First call (or different app ID) — leak strings and cache them
        let leaked_name: &'static str = Box::leak(name.to_owned().into_boxed_str());
        let leaked_desc: &'static str = Box::leak(description.to_owned().into_boxed_str());
        let leaked_url: &'static str = Box::leak(service_url.to_owned().into_boxed_str());
        let leaked_logo: Option<&'static str> =
            logo_url.map(|s| Box::leak(s.into_boxed_str()) as &'static str);
        let leaked_cb: Option<&'static str> =
            callback_url.map(|s| Box::leak(s.into_boxed_str()) as &'static str);

        *cache = Some(CachedMeta {
            id: app_id,
            name: leaked_name,
            description: leaked_desc,
            service_url: leaked_url,
            logo_url: leaked_logo,
            callback_url: leaked_cb,
        });

        Ok(AppMetadata {
            id: app_id,
            name: leaked_name,
            description: leaked_desc,
            service_url: leaked_url,
            logo_url: leaked_logo,
            callback_url: leaked_cb,
        })
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountInfo {
    pub account_key: String,
    pub max_pinned_data: u64,
    pub remaining_storage: u64,
    pub pinned_data: u64,
    pub pinned_size: u64,
    pub ready: bool,
    pub app_name: String,
    pub app_description: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostInfo {
    pub public_key: String,
    pub country_code: String,
    pub good_for_upload: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ObjectInfo {
    pub id: String,
    pub size: u64,
    pub encoded_size: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ObjectEventInfo {
    pub id: String,
    pub deleted: bool,
    pub updated_at: i64,
    pub object: Option<ObjectInfo>,
}

pub(crate) fn object_to_info(obj: &Object) -> ObjectInfo {
    ObjectInfo {
        id: obj.id().to_string(),
        size: obj.size(),
        encoded_size: obj.encoded_size(),
        created_at: obj.created_at().timestamp(),
        updated_at: obj.updated_at().timestamp(),
    }
}
