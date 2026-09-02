use std::str::FromStr;

use sia_core::types::Hash256;
use sia_core::types::v2::Protocol;
use sia_storage::{
    HostQuery as StorageHostQuery, KeyRecord as StorageKeyRecord, SharedSdk as StorageSharedSdk,
    SharingKey as StorageSharingKey,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;
use crate::object::PinnedObject;
use crate::run_local;
use crate::types::{self, HostQuery, KeyStats, download_options_from_js};

/// Decodes the hex seed a sharing key's owner handed out.
fn seed_from_hex(seed: &str) -> Result<[u8; 32], JsError> {
    let bytes = hex::decode(seed.trim()).map_err(to_js_err)?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| JsError::new(&format!("seed must be 32 bytes, got {}", v.len())))
}

/// A sharing key, granting read-only access to the objects attached to it.
///
/// It is just the credential; the operations that use it live on `Sdk`.
#[wasm_bindgen]
pub struct SharingKey {
    inner: StorageSharingKey,
}

impl SharingKey {
    pub(crate) fn new(inner: StorageSharingKey) -> Self {
        Self { inner }
    }

    pub(crate) fn key(&self) -> &StorageSharingKey {
        &self.inner
    }
}

#[wasm_bindgen]
impl SharingKey {
    /// Imports a sharing key from the hex seed its owner handed out.
    ///
    /// Pass the string returned by [seed](Self::seed).
    #[wasm_bindgen(js_name = "fromSeed")]
    pub fn from_seed(seed: &str) -> Result<SharingKey, JsError> {
        Ok(SharingKey {
            inner: StorageSharingKey::import(seed_from_hex(seed)?),
        })
    }

    /// The key's public half, which identifies it.
    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> String {
        self.inner.public_key().to_string()
    }

    /// Returns the seed a recipient needs to read the key's objects, as hex.
    ///
    /// It is the whole credential. Pair it with the indexer's url in
    /// `SharedSdk.connect`.
    pub fn seed(&self) -> String {
        hex::encode(self.inner.export())
    }
}

/// The indexer's record for a sharing key, including how many objects it grants
/// access to and how much space they use. The counts are a snapshot, not a live
/// view.
#[wasm_bindgen]
pub struct KeyRecord {
    inner: StorageKeyRecord,
}

impl KeyRecord {
    pub(crate) fn new(inner: StorageKeyRecord) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl KeyRecord {
    /// The key this record describes.
    #[wasm_bindgen(getter)]
    pub fn key(&self) -> SharingKey {
        SharingKey::new(self.inner.key.clone())
    }

    #[wasm_bindgen(getter)]
    pub fn description(&self) -> String {
        self.inner.description.clone()
    }

    /// A snapshot of how many objects the key grants access to and how much
    /// space they use.
    #[wasm_bindgen(getter)]
    pub fn stats(&self) -> Result<Ts<KeyStats>, JsError> {
        Ok(KeyStats::from(self.inner.stats.clone()).into_ts()?)
    }
}

/// A read-only SDK for the objects a sharing key grants access to.
///
/// Unlike `Sdk`, it authenticates with a sharing key rather than an app key and
/// cannot upload, pin, or delete. Downloads are paid for by the key's owner.
#[wasm_bindgen]
pub struct SharedSdk {
    inner: StorageSharedSdk,
}

#[wasm_bindgen]
impl SharedSdk {
    /// Connects to `indexerUrl` as the recipient of the sharing key derived
    /// from `seed`, which is the hex string the key's owner handed out.
    pub async fn connect(indexer_url: String, seed: String) -> Result<SharedSdk, JsError> {
        let seed = seed_from_hex(&seed)?;
        let inner = StorageSharedSdk::connect(indexer_url, seed)
            .await
            .map_err(to_js_err)?;
        Ok(Self { inner })
    }

    /// Fetches the sharing key's stats from the indexer.
    pub async fn stats(&self) -> Result<Ts<KeyStats>, JsError> {
        let stats: KeyStats = self.inner.stats().await.map_err(to_js_err)?.into();
        Ok(stats.into_ts()?)
    }

    /// Fetches and decrypts one object the key grants access to.
    pub async fn object(&self, id: String) -> Result<PinnedObject, JsError> {
        let id = Hash256::from_str(&id).map_err(to_js_err)?;
        let object = self.inner.object(&id).await.map_err(to_js_err)?;
        Ok(PinnedObject(object))
    }

    /// Lists and decrypts a page of the objects the key grants access to.
    pub async fn objects(&self, offset: u32, limit: u32) -> Result<Vec<PinnedObject>, JsError> {
        let objects = self
            .inner
            .objects(Some(offset as u64), Some(limit as u64))
            .await
            .map_err(to_js_err)?;
        Ok(objects.into_iter().map(PinnedObject).collect())
    }

    /// Returns the hosts serving this key's objects, optionally filtered by a
    /// HostQuery. Mirrors `Sdk.hosts()` but is scoped to the sharing key, so the
    /// set is already limited to hosts holding its objects.
    #[wasm_bindgen(unchecked_return_type = "Host[]")]
    pub async fn hosts(&self, query: Option<Ts<HostQuery>>) -> Result<JsValue, JsError> {
        let sdk = self.inner.clone();
        let q: StorageHostQuery = match query {
            Some(hq) => {
                let mut q: StorageHostQuery = hq.to_rust()?.into();
                q.protocol = Some(Protocol::QUIC);
                q
            }
            None => StorageHostQuery {
                protocol: Some(Protocol::QUIC),
                ..Default::default()
            },
        };
        let hosts = run_local(async move { sdk.hosts(q).await })
            .await
            .map_err(to_js_err)?;
        types::to_js(&hosts)
    }

    /// Streams a shared object's data.
    pub fn download(
        &self,
        object: &PinnedObject,
        options: Option<JsValue>,
    ) -> Result<web_sys::ReadableStream, JsError> {
        const CHUNK_SIZE: usize = 1 << 18;
        let opts = options.map(download_options_from_js).unwrap_or_default();
        let download = self.inner.download(&object.0, opts).map_err(to_js_err)?;
        Ok(wasm_streams::ReadableStream::from_async_read(download.compat(), CHUNK_SIZE).into_raw())
    }
}

// Types the download options, which wasm_bindgen otherwise emits as any.
#[wasm_bindgen(typescript_custom_section)]
const _: &str = r#"
interface SharedSdk {
    download(object: PinnedObject, options?: DownloadOptions): ReadableStream;
}
"#;
