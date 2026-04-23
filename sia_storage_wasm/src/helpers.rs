use js_sys::Reflect;
use sia_core::types::Hash256;
use sia_storage::AppMetadata;
use wasm_bindgen::prelude::*;

pub(crate) fn to_js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

/// Read a required string field from a JS object.
pub(crate) fn js_get_string(obj: &JsValue, key: &str) -> Result<String, JsError> {
    let val = Reflect::get(obj, &JsValue::from_str(key))
        .map_err(|e| JsError::new(&format!("read field `{key}`: {e:?}")))?;
    val.as_string()
        .ok_or_else(|| JsError::new(&format!("field `{key}` missing or not a string")))
}

/// Read an optional string field from a JS object.
pub(crate) fn js_get_opt_string(obj: &JsValue, key: &str) -> Option<String> {
    Reflect::get(obj, &JsValue::from_str(key))
        .ok()
        .and_then(|v| v.as_string())
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
    static CACHED_META: std::cell::RefCell<Option<CachedMeta>> = const { std::cell::RefCell::new(None) };
}

/// Constructs an [`AppMetadata`] from a JS object matching the
/// `AppMetadata` TS interface declared in `types.rs`. Fields are read
/// via `js_sys::Reflect` instead of `#[tsify(from_wasm_abi)]` because
/// that path is broken for plain-JS-constructed inputs. Field names
/// here must stay in sync with the TS interface.
///
/// `AppMetadata` requires `&'static str` fields, but strings from JS are
/// temporary. We use `Box::leak` to promote each string to `'static`
/// references. The leaked strings are cached so this only happens once —
/// subsequent calls with the same app ID reuse the cached references.
pub(crate) fn make_app_metadata(app: &JsValue) -> Result<AppMetadata, JsError> {
    let id_hex = js_get_string(app, "appId")?;
    let name = js_get_string(app, "name")?;
    let description = js_get_string(app, "description")?;
    let service_url = js_get_string(app, "serviceUrl")?;
    let logo_url = js_get_opt_string(app, "logoUrl");
    let callback_url = js_get_opt_string(app, "callbackUrl");

    let id_bytes = hex::decode(&id_hex).map_err(to_js_err)?;
    if id_bytes.len() != 32 {
        return Err(JsError::new("app ID must be 32 bytes (64 hex chars)"));
    }
    let app_id =
        Hash256::from(<[u8; 32]>::try_from(id_bytes).expect("length validated as 32 above"));

    CACHED_META.with(|cell| {
        let mut cache = cell.borrow_mut();

        // Return cached metadata if the app ID matches
        if let Some(ref c) = *cache
            && c.id == app_id
        {
            return Ok(AppMetadata {
                id: c.id,
                name: c.name,
                description: c.description,
                service_url: c.service_url,
                logo_url: c.logo_url,
                callback_url: c.callback_url,
            });
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
