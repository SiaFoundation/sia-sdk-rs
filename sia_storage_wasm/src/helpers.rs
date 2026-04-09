use sia_core::types::Hash256;
use sia_storage::AppMetadata;
use wasm_bindgen::prelude::*;

pub(crate) fn to_js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
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
    let app_id =
        Hash256::from(<[u8; 32]>::try_from(id_bytes).expect("length validated as 32 above"));

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

/// Account information returned by `Sdk.account()`.
#[wasm_bindgen(getter_with_clone)]
pub struct Account {
    #[wasm_bindgen(js_name = "accountKey")]
    pub account_key: String,
    #[wasm_bindgen(js_name = "maxPinnedData")]
    pub max_pinned_data: u64,
    #[wasm_bindgen(js_name = "remainingStorage")]
    pub remaining_storage: u64,
    #[wasm_bindgen(js_name = "pinnedData")]
    pub pinned_data: u64,
    #[wasm_bindgen(js_name = "pinnedSize")]
    pub pinned_size: u64,
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
}
