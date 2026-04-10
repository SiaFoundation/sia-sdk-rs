use sia_core::types::Hash256;
use sia_storage::AppMetadata;
use wasm_bindgen::prelude::*;

pub(crate) fn to_js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

struct CachedMeta {
    id: Hash256,
    name: &'static str,
    description: &'static str,
    service_url: &'static str,
    logo_url: Option<&'static str>,
    callback_url: Option<&'static str>,
}

thread_local! {
    static CACHED_META: std::cell::RefCell<Option<CachedMeta>> = std::cell::RefCell::new(None);
}

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
    let app_id =
        Hash256::from(<[u8; 32]>::try_from(id_bytes).expect("length validated as 32 above"));

    CACHED_META.with(|cell| {
        let mut cache = cell.borrow_mut();
        if let Some(ref c) = *cache {
            if c.id == app_id {
                return Ok(AppMetadata {
                    id: c.id, name: c.name, description: c.description,
                    service_url: c.service_url, logo_url: c.logo_url, callback_url: c.callback_url,
                });
            }
        }
        let leaked_name: &'static str = Box::leak(name.to_owned().into_boxed_str());
        let leaked_desc: &'static str = Box::leak(description.to_owned().into_boxed_str());
        let leaked_url: &'static str = Box::leak(service_url.to_owned().into_boxed_str());
        let leaked_logo: Option<&'static str> = logo_url.map(|s| Box::leak(s.into_boxed_str()) as &'static str);
        let leaked_cb: Option<&'static str> = callback_url.map(|s| Box::leak(s.into_boxed_str()) as &'static str);
        *cache = Some(CachedMeta {
            id: app_id, name: leaked_name, description: leaked_desc,
            service_url: leaked_url, logo_url: leaked_logo, callback_url: leaked_cb,
        });
        Ok(AppMetadata {
            id: app_id, name: leaked_name, description: leaked_desc,
            service_url: leaked_url, logo_url: leaked_logo, callback_url: leaked_cb,
        })
    })
}
