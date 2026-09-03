use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use sia_core::types::Hash256;
use tokio_util::sync::CancellationToken;

use crate::{Download, DownloadError, DownloadOptions, Error, Host, PinnedObject, Sdk, spawn};

fn seed_from_vec(seed: Vec<u8>) -> Result<[u8; 32], Error> {
    seed.try_into()
        .map_err(|_| Error::Custom("seed must be 32 bytes".into()))
}

/// A snapshot of what a sharing key grants access to. The counts reflect the
/// moment the record was fetched, not a live view.
#[derive(uniffi::Record)]
pub struct KeyStats {
    pub object_count: u64,
    pub object_size: u64,
    pub pinned_data: u64,
    pub pinned_size: u64,
    pub expires_at: Option<SystemTime>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

impl From<sia_storage::KeyStats> for KeyStats {
    fn from(s: sia_storage::KeyStats) -> Self {
        Self {
            object_count: s.object_count,
            object_size: s.object_size,
            pinned_data: s.pinned_data,
            pinned_size: s.pinned_size,
            expires_at: s.expires_at.map(|d| d.into()),
            created_at: s.created_at.into(),
            updated_at: s.updated_at.into(),
        }
    }
}

/// A sharing key, granting read-only access to the objects attached to it.
///
/// It is just the credential; the operations that use it live on `Sdk`.
#[derive(uniffi::Object)]
pub struct SharingKey {
    inner: sia_storage::SharingKey,
}

impl SharingKey {
    pub(crate) fn new(inner: sia_storage::SharingKey) -> Self {
        Self { inner }
    }
}

#[uniffi::export]
impl SharingKey {
    /// Imports a sharing key from the 32-byte seed its owner handed out.
    #[uniffi::constructor]
    pub fn from_seed(seed: Vec<u8>) -> Result<SharingKey, Error> {
        Ok(SharingKey {
            inner: sia_storage::SharingKey::import(seed_from_vec(seed)?),
        })
    }

    /// The key's public half, which identifies it on the indexer.
    pub fn public_key(&self) -> String {
        self.inner.public_key().to_string()
    }

    /// The 32-byte seed a recipient needs to read the key's objects. Pair it
    /// with the indexer url in `SharedSdk::connect`.
    pub fn seed(&self) -> Vec<u8> {
        self.inner.export().to_vec()
    }
}

/// The indexer's record for a sharing key, including how many objects it grants
/// access to and how much space they use.
#[derive(uniffi::Record)]
pub struct KeyRecord {
    /// The key this record describes.
    pub key: Arc<SharingKey>,
    pub description: String,
    /// A snapshot of how many objects the key grants access to and how much
    /// space they use.
    pub stats: KeyStats,
}

impl From<sia_storage::KeyRecord> for KeyRecord {
    fn from(r: sia_storage::KeyRecord) -> Self {
        Self {
            key: Arc::new(SharingKey::new(r.key)),
            description: r.description,
            stats: r.stats.into(),
        }
    }
}

#[uniffi::export]
impl Sdk {
    /// Creates a sharing key. Attach objects to it with `Sdk::share_object`.
    pub async fn create_sharing_key(
        &self,
        description: String,
        expires_at: Option<SystemTime>,
    ) -> Result<SharingKey, Error> {
        let sdk = self.inner.clone();
        spawn(async move {
            let key = sdk
                .create_sharing_key(sia_storage::SharingKeyOptions {
                    description,
                    expires_at: expires_at.map(|t| t.into()),
                })
                .await
                .map_err(|e| Error::Custom(e.to_string()))?;
            Ok(SharingKey::new(key))
        })
        .await?
    }

    /// Lists the account's sharing keys, most recently created first.
    pub async fn sharing_keys(&self, offset: u32, limit: u32) -> Result<Vec<KeyRecord>, Error> {
        let sdk = self.inner.clone();
        spawn(async move {
            let records = sdk
                .sharing_keys(Some(offset as u64), Some(limit as u64))
                .await
                .map_err(|e| Error::Custom(e.to_string()))?;
            Ok(records.into_iter().map(KeyRecord::from).collect())
        })
        .await?
    }

    /// Fetches the indexer's record for a key, including its counts.
    pub async fn sharing_key(&self, key: Arc<SharingKey>) -> Result<KeyRecord, Error> {
        let sdk = self.inner.clone();
        let k = key.inner.clone();
        spawn(async move {
            let record = sdk
                .sharing_key(&k)
                .await
                .map_err(|e| Error::Custom(e.to_string()))?;
            Ok(KeyRecord::from(record))
        })
        .await?
    }

    /// Attaches an object to a sharing key, re-sealing its encryption keys under
    /// the key so recipients can decrypt it.
    pub async fn share_object(
        &self,
        key: Arc<SharingKey>,
        object: Arc<PinnedObject>,
    ) -> Result<(), Error> {
        let sdk = self.inner.clone();
        let k = key.inner.clone();
        let obj = object.object();
        spawn(async move {
            sdk.share_object(&k, &obj)
                .await
                .map_err(|e| Error::Custom(e.to_string()))?;
            Ok(())
        })
        .await?
    }

    /// Lists and decrypts the objects attached to a sharing key.
    pub async fn shared_objects(
        &self,
        key: Arc<SharingKey>,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Arc<PinnedObject>>, Error> {
        let sdk = self.inner.clone();
        let k = key.inner.clone();
        spawn(async move {
            let objects = sdk
                .shared_objects(&k, Some(offset as u64), Some(limit as u64))
                .await
                .map_err(|e| Error::Custom(e.to_string()))?;
            Ok(objects
                .into_iter()
                .map(|o| {
                    Arc::new(PinnedObject {
                        inner: Arc::new(Mutex::new(o)),
                    })
                })
                .collect())
        })
        .await?
    }

    /// Detaches an object from a sharing key.
    pub async fn unshare_object(&self, key: Arc<SharingKey>, id: String) -> Result<(), Error> {
        let sdk = self.inner.clone();
        let k = key.inner.clone();
        let id = Hash256::from_str(&id)?;
        spawn(async move {
            sdk.unshare_object(&k, &id)
                .await
                .map_err(|e| Error::Custom(e.to_string()))?;
            Ok(())
        })
        .await?
    }

    /// Revokes a sharing key, deleting it and detaching all of its objects.
    pub async fn revoke_sharing_key(&self, key: Arc<SharingKey>) -> Result<(), Error> {
        let sdk = self.inner.clone();
        let k = key.inner.clone();
        spawn(async move {
            sdk.revoke_sharing_key(&k)
                .await
                .map_err(|e| Error::Custom(e.to_string()))?;
            Ok(())
        })
        .await?
    }
}

/// A read-only SDK for the objects a sharing key grants access to.
///
/// Unlike `Sdk`, it authenticates with a sharing key rather than an app key and
/// cannot upload, pin, or delete. Downloads are paid for by the key's owner.
#[derive(uniffi::Object)]
pub struct SharedSdk {
    inner: sia_storage::SharedSdk,
}

#[uniffi::export]
impl SharedSdk {
    /// Connects to `indexer_url` as the recipient of the sharing key derived
    /// from `seed`, the 32-byte seed the key's owner handed out.
    #[uniffi::constructor]
    pub async fn connect(indexer_url: String, seed: Vec<u8>) -> Result<SharedSdk, Error> {
        let seed = seed_from_vec(seed)?;
        let inner = spawn(async move {
            sia_storage::SharedSdk::connect(indexer_url, seed)
                .await
                .map_err(|e| Error::Custom(e.to_string()))
        })
        .await??;
        Ok(SharedSdk { inner })
    }

    /// Fetches the sharing key's stats from the indexer.
    pub async fn stats(&self) -> Result<KeyStats, Error> {
        let shared = self.inner.clone();
        spawn(async move {
            let stats = shared.stats().await?;
            Ok(stats.into())
        })
        .await?
    }

    /// Fetches and decrypts one object the key grants access to.
    pub async fn object(&self, id: String) -> Result<PinnedObject, Error> {
        let shared = self.inner.clone();
        let id = Hash256::from_str(&id)?;
        spawn(async move {
            let object = shared.object(&id).await?;
            Ok(PinnedObject {
                inner: Arc::new(Mutex::new(object)),
            })
        })
        .await?
    }

    /// Lists and decrypts a page of the objects the key grants access to.
    pub async fn objects(&self, offset: u32, limit: u32) -> Result<Vec<Arc<PinnedObject>>, Error> {
        let shared = self.inner.clone();
        spawn(async move {
            let objects = shared
                .objects(Some(offset as u64), Some(limit as u64))
                .await?;
            Ok(objects
                .into_iter()
                .map(|o| {
                    Arc::new(PinnedObject {
                        inner: Arc::new(Mutex::new(o)),
                    })
                })
                .collect())
        })
        .await?
    }

    /// Returns the hosts serving this key's objects. Mirrors `Sdk::hosts` but is
    /// scoped to the sharing key, so the set is already limited to hosts holding
    /// its objects.
    pub async fn hosts(&self) -> Result<Vec<Host>, Error> {
        let shared = self.inner.clone();
        spawn(async move {
            let hosts = shared.hosts(Default::default()).await?;
            Ok(hosts.into_iter().map(|h| h.into()).collect())
        })
        .await?
    }

    /// Streams a shared object's data, paying hosts with the owner's tokens.
    pub fn download(
        &self,
        object: Arc<PinnedObject>,
        options: DownloadOptions,
    ) -> Result<Download, DownloadError> {
        // Enter the runtime so Download::new's spawned recovery tasks have a
        // reactor in scope.
        let _guard = crate::RUNTIME.handle().enter();
        let reader = self.inner.download(&object.object(), options.into())?;
        Ok(Download {
            inner: Arc::new(tokio::sync::Mutex::new(Some(reader))),
            cancel: CancellationToken::new(),
        })
    }
}
