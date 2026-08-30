use chrono::{DateTime, Utc};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use sia_core::types::{Hash256, HexParseError};
use std::str::FromStr;
use std::sync::Mutex;
use tokio_stream::StreamExt;

use crate::{DownloadOptions, Host, PinnedObject, Sdk, io};

fn seed_from_buffer(seed: Buffer) -> Result<[u8; 32]> {
    seed.as_ref()
        .try_into()
        .map_err(|_| Error::from_reason("seed must be 32 bytes"))
}

/// A snapshot of what a sharing key grants access to. The counts reflect the
/// moment the record was fetched, not a live view.
#[napi(object)]
pub struct KeyStats {
    pub object_count: BigInt,
    pub object_size: BigInt,
    pub pinned_data: BigInt,
    pub pinned_size: BigInt,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<sia_storage::KeyStats> for KeyStats {
    fn from(s: sia_storage::KeyStats) -> Self {
        Self {
            object_count: BigInt::from(s.object_count),
            object_size: BigInt::from(s.object_size),
            pinned_data: BigInt::from(s.pinned_data),
            pinned_size: BigInt::from(s.pinned_size),
            expires_at: s.expires_at,
            created_at: s.created_at,
            updated_at: s.updated_at,
        }
    }
}

/// A sharing key, granting read-only access to the objects attached to it.
///
/// It is just the credential; the operations that use it live on `Sdk`.
#[napi]
pub struct SharingKey {
    inner: sia_storage::SharingKey,
}

impl SharingKey {
    pub(crate) fn new(inner: sia_storage::SharingKey) -> Self {
        Self { inner }
    }

    pub(crate) fn key(&self) -> &sia_storage::SharingKey {
        &self.inner
    }
}

#[napi]
impl SharingKey {
    /// The key's public half, which identifies it on the indexer.
    #[napi(getter)]
    pub fn public_key(&self) -> String {
        self.inner.public_key().to_string()
    }

    /// The 32-byte seed a recipient needs to read the key's objects. Pair it
    /// with the indexer url in `SharedSdk.connect`.
    #[napi]
    pub fn seed(&self) -> Buffer {
        Buffer::from(self.inner.export().to_vec())
    }

    /// Imports a sharing key from the 32-byte seed its owner handed out.
    #[napi(factory)]
    pub fn from_seed(seed: Buffer) -> Result<SharingKey> {
        Ok(SharingKey {
            inner: sia_storage::SharingKey::import(seed_from_buffer(seed)?),
        })
    }
}

/// The indexer's record for a sharing key, including how many objects it grants
/// access to and how much space they use.
#[napi]
pub struct KeyRecord {
    inner: sia_storage::KeyRecord,
}

#[napi]
impl KeyRecord {
    /// The key this record describes.
    #[napi(getter)]
    pub fn key(&self) -> SharingKey {
        SharingKey::new(self.inner.key.clone())
    }

    #[napi(getter)]
    pub fn description(&self) -> String {
        self.inner.description.clone()
    }

    /// A snapshot of how many objects the key grants access to and how much
    /// space they use.
    #[napi(getter)]
    pub fn stats(&self) -> KeyStats {
        self.inner.stats.clone().into()
    }
}

#[napi]
impl Sdk {
    /// Creates a sharing key. Attach objects to it with `Sdk.shareObject`.
    #[napi]
    pub async fn create_sharing_key(
        &self,
        description: String,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<SharingKey> {
        let key = self
            .inner
            .create_sharing_key(sia_storage::SharingKeyOptions {
                description,
                expires_at,
            })
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(SharingKey::new(key))
    }

    /// Lists the account's sharing keys, most recently created first.
    #[napi]
    pub async fn sharing_keys(&self, offset: u32, limit: u32) -> Result<Vec<KeyRecord>> {
        let records = self
            .inner
            .sharing_keys(Some(offset as u64), Some(limit as u64))
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(records
            .into_iter()
            .map(|inner| KeyRecord { inner })
            .collect())
    }

    /// Fetches the indexer's record for a key, including its counts.
    #[napi]
    pub async fn sharing_key(&self, key: &SharingKey) -> Result<KeyRecord> {
        let inner = self
            .inner
            .sharing_key(key.key())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(KeyRecord { inner })
    }

    /// Attaches an object to a sharing key, re-sealing its encryption keys under
    /// the key so recipients can decrypt it.
    #[napi]
    pub async fn share_object(&self, key: &SharingKey, object: &PinnedObject) -> Result<()> {
        self.inner
            .share_object(key.key(), &object.object())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Lists and decrypts the objects attached to a sharing key.
    #[napi]
    pub async fn shared_objects(
        &self,
        key: &SharingKey,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<PinnedObject>> {
        let objects = self
            .inner
            .shared_objects(key.key(), Some(offset as u64), Some(limit as u64))
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(objects
            .into_iter()
            .map(|o| PinnedObject {
                inner: Mutex::new(o),
            })
            .collect())
    }

    /// Detaches an object from a sharing key.
    #[napi]
    pub async fn unshare_object(&self, key: &SharingKey, id: String) -> Result<()> {
        let id =
            Hash256::from_str(&id).map_err(|e: HexParseError| Error::from_reason(e.to_string()))?;
        self.inner
            .unshare_object(key.key(), &id)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Revokes a sharing key, deleting it and detaching all of its objects.
    #[napi]
    pub async fn revoke_sharing_key(&self, key: &SharingKey) -> Result<()> {
        self.inner
            .revoke_sharing_key(key.key())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}

/// A read-only SDK for the objects a sharing key grants access to.
///
/// Unlike `Sdk`, it authenticates with a sharing key rather than an app key and
/// cannot upload, pin, or delete. Downloads are paid for by the key's owner.
#[napi]
pub struct SharedSdk {
    inner: sia_storage::SharedSdk,
}

#[napi]
impl SharedSdk {
    /// Connects to `indexer_url` as the recipient of the sharing key derived
    /// from `seed`, the 32-byte seed the key's owner handed out.
    #[napi]
    pub async fn connect(indexer_url: String, seed: Buffer) -> Result<SharedSdk> {
        let inner = sia_storage::SharedSdk::connect(indexer_url, seed_from_buffer(seed)?)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(SharedSdk { inner })
    }

    /// Fetches the sharing key's stats from the indexer.
    #[napi]
    pub async fn stats(&self) -> Result<KeyStats> {
        Ok(self
            .inner
            .stats()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?
            .into())
    }

    /// Fetches and decrypts one object the key grants access to.
    #[napi]
    pub async fn object(&self, id: String) -> Result<PinnedObject> {
        let id =
            Hash256::from_str(&id).map_err(|e: HexParseError| Error::from_reason(e.to_string()))?;
        let object = self
            .inner
            .object(&id)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(PinnedObject {
            inner: Mutex::new(object),
        })
    }

    /// Lists and decrypts a page of the objects the key grants access to.
    #[napi]
    pub async fn objects(&self, offset: u32, limit: u32) -> Result<Vec<PinnedObject>> {
        let objects = self
            .inner
            .objects(Some(offset as u64), Some(limit as u64))
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(objects
            .into_iter()
            .map(|o| PinnedObject {
                inner: Mutex::new(o),
            })
            .collect())
    }

    /// Returns the hosts serving this key's objects. Mirrors `Sdk.hosts()` but
    /// is scoped to the sharing key, so the set is already limited to hosts
    /// holding its objects.
    #[napi]
    pub async fn hosts(&self) -> Result<Vec<Host>> {
        let hosts = self
            .inner
            .hosts(Default::default())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(hosts.into_iter().map(|h| h.into()).collect())
    }

    /// Streams a shared object's data, paying hosts with the owner's tokens.
    #[napi(ts_return_type = "ReadableStream")]
    pub fn download(
        &self,
        env: Env,
        object: &PinnedObject,
        options: Option<DownloadOptions>,
    ) -> Result<ReadableStream<'_, Buffer>> {
        let object = object.object();
        let download_opts: sia_storage::DownloadOptions = options
            .map(|o| o.try_into())
            .transpose()?
            .unwrap_or_default();

        let stream = within_runtime_if_available(|| {
            let reader = self
                .inner
                .download(&object, download_opts)
                .map_err(|e| Error::from_reason(e.to_string()))?;
            Ok::<_, Error>(io::AsyncReadStream::new(reader).map(|r| {
                r.map(Buffer::from)
                    .map_err(|e| Error::from_reason(e.to_string()))
            }))
        })?;
        ReadableStream::new(&env, stream)
    }
}
