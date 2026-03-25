/// Run a blocking computation on `spawn_blocking` on native, or inline on WASM.
/// Must be called from an async context. The expression must return a type that
/// implements `Send + 'static` on native.
///
/// ```ignore
/// let result = maybe_spawn_blocking!(expensive_computation())?;
/// ```
macro_rules! maybe_spawn_blocking {
    ($body:expr) => {{
        #[cfg(not(target_arch = "wasm32"))]
        {
            tokio::task::spawn_blocking(move || $body).await?
        }
        #[cfg(target_arch = "wasm32")]
        {
            $body
        }
    }};
}

/// Spawn a future on a [`tokio::task::JoinSet`]. Uses `spawn` on native
/// (requires `Send`) and `spawn_local` on WASM (no `Send` required).
///
/// ```ignore
/// let mut set = tokio::task::JoinSet::new();
/// join_set_spawn!(set, async move { do_work().await });
/// ```
macro_rules! join_set_spawn {
    ($set:expr, $fut:expr) => {{
        #[cfg(not(target_arch = "wasm32"))]
        $set.spawn($fut);
        #[cfg(target_arch = "wasm32")]
        $set.spawn_local($fut);
    }};
}

use std::sync::Arc;

use log::debug;
use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::app_client::SlabPinParams;
use crate::download::Downloader;
use crate::hosts::Hosts;
use crate::rhp4::HostEndpoint;
#[cfg(not(target_arch = "wasm32"))]
use crate::rhp4::siamux::Client as TransportClient;
use crate::upload::Uploader;
#[cfg(target_arch = "wasm32")]
use crate::web_transport::Client as TransportClient;

mod app_client;
mod builder;
mod download;
mod encryption;
mod erasure_coding;
mod hosts;
mod object_encryption;
mod rhp4;
mod slabs;
mod upload;

#[cfg(target_arch = "wasm32")]
pub(crate) mod wasm_time;

/// Unified time module for native and WASM targets.
///
/// All time-related imports throughout the codebase MUST come from
/// `crate::time`. Do not import from `std::time`, `tokio::time`,
/// `web_time`, or `wasm_time` directly in other modules.
pub(crate) mod time {
    pub use web_time::{Duration, Instant};

    #[cfg(not(target_arch = "wasm32"))]
    pub use tokio::time::{error::Elapsed, sleep, timeout};

    #[cfg(target_arch = "wasm32")]
    pub use super::wasm_time::{Elapsed, sleep, timeout};
}

/// Unified task utilities for native and WASM targets.
///
/// Import from `crate::task` instead of `tokio::task` or `tokio_util::task`
/// directly in other modules.
pub(crate) mod task {
    /// A wrapper around [`tokio::task::JoinHandle`] that aborts the task
    /// when dropped. Replaces `tokio_util::task::AbortOnDropHandle` with
    /// a cross-platform implementation that works on both native and WASM.
    pub struct AbortOnDropHandle<T>(pub tokio::task::JoinHandle<T>);

    impl<T> Drop for AbortOnDropHandle<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    impl<T> AbortOnDropHandle<T> {
        pub fn new(handle: tokio::task::JoinHandle<T>) -> Self {
            Self(handle)
        }
    }

    impl<T> std::future::Future for AbortOnDropHandle<T> {
        type Output = Result<T, tokio::task::JoinError>;

        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::pin::Pin::new(&mut self.0).poll(cx)
        }
    }
}

#[cfg(any(test, feature = "mock"))]
pub mod mock;

// re-export types for easier access
pub use crate::hosts::Host;
pub use chrono::{DateTime, Utc};
pub use reqwest::{IntoUrl, Url};
#[doc(hidden)]
pub use sia_core::macros::decode_hex_256;
pub use sia_core::seed::SeedError;
pub use sia_core::signing::{PrivateKey, PublicKey};
pub use sia_core::types::Hash256;
pub use sia_core::types::v2::Protocol;

pub use app_client::{Account, App, Error as AppApiError, GeoLocation, HostQuery, ObjectsCursor};
pub use builder::{
    ApprovedState, Builder, BuilderError, DisconnectedState, RequestingApprovalState,
};
pub use download::{DownloadError, DownloadOptions};
pub use encryption::EncryptionKey;
pub use hosts::QueueError;
pub use slabs::{Object, ObjectEvent, PinnedSlab, SealedObject, SealedObjectError, Sector, Slab};
pub use upload::{PackedUpload, UploadError, UploadOptions};

/// A unique identifier for an indexer application. It should be constant for an application.
pub type AppID = Hash256;

/// A macro to create an [AppID] from a literal hex string. The string must be 64 characters long.
///
/// ```
/// use sia_storage::{AppID, app_id};
///
/// const MY_APP_ID: AppID = app_id!("0e90d697f5045a6593f1c43ebf79a369e2bc72cc5c7b6282f3b5aeb0de6e4005");
/// ```
#[macro_export]
macro_rules! app_id {
    ($text:literal) => {
        $crate::Hash256::new($crate::decode_hex_256($text.as_bytes()))
    };
}

/// Application metadata for registering with an indexer.
///
/// This should be defined as a constant in the application and passed to the [Builder] when creating an SDK instance.
/// The metadata is used during registration to create the application on the indexer and should not change between
/// runs of the application.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppMetadata {
    #[serde(rename = "appID")]
    pub id: AppID,
    /// A human-readable name for the application. This is used for display purposes on the indexer
    /// and should be unique to avoid confusion with other applications.
    ///
    /// Max length 128 characters.
    pub name: &'static str,
    /// A brief description of the application. This is used for display purposes on the indexer
    /// and should be concise and informative.
    ///
    /// Max length 1024 characters.
    pub description: &'static str,
    #[serde(rename = "serviceURL")]
    /// A URL where the application can be accessed or contacted. This is used for display purposes on the indexer
    /// and should be a valid URL that points to the application's website or support page.
    ///
    /// Max length 1024 characters.
    pub service_url: &'static str,
    #[serde(rename = "logoURL")]
    /// An optional URL pointing to the application's logo. This is used for display purposes on the indexer
    /// and should be a valid URL that points to an image file (e.g., PNG, JPEG) that represents the application's logo.
    ///
    /// Max length 1024 characters.
    pub logo_url: Option<&'static str>,

    /// An optional URL the indexer will call after the application is authorized
    ///
    /// Max length 1024 characters.
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<&'static str>,
}

/// Errors that can occur when using the SDK.
#[derive(Error, Debug)]
pub enum Error {
    #[error("app error: {0}")]
    App(String),

    #[error("upload error: {0}")]
    Upload(#[from] UploadError),

    #[error("download error: {0}")]
    Download(#[from] DownloadError),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("sealed object: {0}")]
    SealedObject(#[from] SealedObjectError),
}

/// The main interface with interacting with the Sia storage network. It provides methods for uploading and downloading objects, as well as managing hosts and account information.
#[derive(Clone)]
pub struct SDK {
    app_key: Arc<PrivateKey>,
    api_client: app_client::Client,
    hosts: Hosts<siamux::Client>,
    downloader: Downloader<siamux::Client>,
    uploader: Uploader<siamux::Client>,
}

impl SDK {
    async fn refresh_hosts(&self) -> Result<(), AppApiError> {
        const PAGE_SIZE: usize = 100;
        let mut good_for_upload = Vec::new();
        let mut total_hosts: usize = 0;
        for i in (0..).step_by(PAGE_SIZE) {
            let usable_hosts = self
                .api_client
                .hosts(
                    &self.app_key,
                    HostQuery {
                        offset: Some(i),
                        limit: Some(PAGE_SIZE as u64),
                        ..Default::default()
                    },
                )
                .await?;
            let n = usable_hosts.len();
            total_hosts += n;
            usable_hosts
                .iter()
                .filter(|h| h.good_for_upload)
                .map(|h| HostEndpoint {
                    public_key: h.public_key,
                    addresses: h.addresses.clone(),
                })
                .for_each(|h| good_for_upload.push(h));
            self.hosts.update(usable_hosts, i == 0);
            if n < PAGE_SIZE {
                break;
            }
        }
        debug!(
            "Refreshed hosts: total {}, good for upload {}",
            total_hosts,
            good_for_upload.len()
        );
        let _ = self.hosts.warm_connections(good_for_upload).await;
        Ok(())
    }

    /// Creates a new SDK instance.
    async fn new(
        api_client: app_client::Client,
        app_key: Arc<PrivateKey>,
    ) -> Result<Self, BuilderError> {
        let transport = Client::new();
        let hosts = Hosts::new(transport);

        let downloader = Downloader::new(hosts.clone(), app_key.clone());
        let uploader = Uploader::new(hosts.clone(), app_key.clone());
        let sdk = Self {
            app_key,
            api_client,
            hosts,
            downloader,
            uploader,
        };
        sdk.refresh_hosts().await?;
        Ok(sdk)
    }

    /// Returns the application key used by the SDK.
    ///
    /// This should be kept secret and secure. Applications
    /// should store it safely.
    pub fn app_key(&self) -> &PrivateKey {
        &self.app_key
    }

    /// Reads until EOF and uploads all slabs.
    /// The data will be erasure coded, encrypted,
    /// and uploaded using the uploader's parameters.
    ///
    /// # Arguments
    /// * `r` - The reader to read the data from. It will be read until EOF.
    /// * `options` - The [UploadOptions] to use for the upload.
    ///
    /// # Returns
    /// A new object containing the metadata needed to download the object. The object can be sealed and pinned to the
    /// indexer when ready.
    pub async fn upload<R: AsyncRead + Unpin + Send + 'static>(
        &self,
        reader: R,
        options: UploadOptions,
    ) -> Result<Object, UploadError> {
        let object = self.uploader.upload(reader, options).await?;
        Ok(object)
    }

    /// Creates a new packed upload. This allows multiple objects to be packed together
    /// for more efficient uploads. The returned `PackedUpload` can be used to add objects to the upload, and then finalized to get the resulting objects.
    ///
    /// # Arguments
    /// * `options` - The [UploadOptions] to use for the upload.
    ///
    /// # Returns
    /// A [PackedUpload] that can be used to add objects and finalize the upload.
    pub fn upload_packed(&self, options: UploadOptions) -> PackedUpload {
        self.uploader.upload_packed(options)
    }

    /// Downloads an object using the provided writer and options.
    pub async fn download<W: AsyncWrite + Unpin>(
        &self,
        w: &mut W,
        object: &Object,
        options: DownloadOptions,
    ) -> Result<(), DownloadError> {
        self.downloader.download(w, object, options).await?;
        Ok(())
    }

    /// Retrieves a list of hosts from the indexer matching the provided query
    /// that can be used for uploading and downloading data.
    ///
    /// # Arguments
    /// * `query` - Filtering criteria to select hosts.
    pub async fn hosts(&self, query: HostQuery) -> Result<Vec<Host>, Error> {
        self.api_client
            .hosts(&self.app_key, query)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Retrieves account information from the indexer.
    pub async fn account(&self) -> Result<Account, Error> {
        self.api_client
            .account(&self.app_key)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Retrieves an object from the indexer by its key.
    ///
    /// # Arguments
    /// * `key` - The key of the object to retrieve.
    pub async fn object(&self, key: &Hash256) -> Result<Object, Error> {
        let sealed = self
            .api_client
            .object(&self.app_key, key)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        let obj = sealed.open(&self.app_key)?;
        Ok(obj)
    }

    /// Retrieves a list of object events from the indexer. This
    /// can be used to synchronize local state with the indexer.
    ///
    /// # Arguments
    /// * `cursor` - An optional cursor to continue from a previous call.
    /// * `limit` - An optional limit on the number of events to retrieve.
    pub async fn object_events(
        &self,
        cursor: Option<ObjectsCursor>,
        limit: Option<usize>,
    ) -> Result<Vec<ObjectEvent>, Error> {
        let events = self
            .api_client
            .objects(&self.app_key, cursor, limit)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        let objs = events
            .into_iter()
            .map(|event| {
                let object = match event.object {
                    Some(sealed) => Some(sealed.open(&self.app_key)?),
                    None => None,
                };
                Ok(ObjectEvent {
                    id: event.id,
                    deleted: event.deleted,
                    updated_at: event.updated_at,
                    object,
                })
            })
            .collect::<Result<_, Error>>()?;

        Ok(objs)
    }

    /// Prunes unused slabs from the indexer. This helps to free up
    /// storage space by removing slabs that are no longer
    /// referenced by objects.
    pub async fn prune_slabs(&self) -> Result<(), Error> {
        self.api_client
            .prune_slabs(&self.app_key)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        Ok(())
    }

    /// Updates the metadata of an object in the indexer. The object
    /// must already be pinned to the indexer.
    ///
    /// # Arguments
    /// * `object` - The object to update.
    pub async fn update_object_metadata(&self, object: &Object) -> Result<(), Error> {
        let sealed = object.seal(&self.app_key);
        self.api_client
            .pin_object(&self.app_key, &sealed)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        Ok(())
    }

    /// Deletes the object with the given id.
    ///
    /// # Arguments
    /// * `id` - The id of the object to delete.
    pub async fn delete_object(&self, id: &Hash256) -> Result<(), Error> {
        self.api_client
            .delete_object(&self.app_key, id)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Generates a shared URL for the given object that is valid until the specified time.
    ///
    /// This object should be considered public even if the URL is kept secret,
    /// as anyone with the URL can access the object until the expiration time.
    ///
    /// # Arguments
    /// * `object` - The object to share.
    /// * `valid_until` - The time until which the shared URL is valid.
    pub fn share_object(&self, object: &Object, valid_until: DateTime<Utc>) -> Result<Url, Error> {
        self.api_client
            .shared_object_url(&self.app_key, object, valid_until)
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Retrieves a shared object from the given share URL.
    ///
    /// # Arguments
    /// * `share_url` - The URL of the shared object.
    pub async fn shared_object<U: IntoUrl>(&self, share_url: U) -> Result<Object, Error> {
        let share_url = share_url
            .into_url()
            .map_err(|e| Error::App(format!("{e:?}")))?;
        self.api_client
            .shared_object(share_url)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Pins an object to the indexer
    pub async fn pin_object(&self, object: &Object) -> Result<(), Error> {
        let slabs = object
            .slabs()
            .iter()
            .map(|s| SlabPinParams {
                encryption_key: s.encryption_key.clone(),
                min_shards: s.min_shards,
                sectors: s.sectors.clone(),
            })
            .collect();

        self.api_client
            .pin_slabs(&self.app_key, slabs)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        self.api_client
            .pin_object(&self.app_key, &object.seal(&self.app_key))
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        Ok(())
    }

    /// Retrieves a pinned slab from the indexer by its id.
    pub async fn slab(&self, id: &Hash256) -> Result<PinnedSlab, Error> {
        self.api_client
            .slab(&self.app_key, id)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }
}

/// Generates a new BIP-39 12-word recovery phrase.
pub fn generate_recovery_phrase() -> String {
    sia_core::seed::Seed::from_seed(rand::random::<[u8; 16]>()).to_string()
}

/// Validates a BIP-39 recovery phrase.
pub fn validate_recovery_phrase(phrase: &str) -> Result<(), SeedError> {
    sia_core::seed::Seed::new(phrase)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use bytes::{Bytes, BytesMut};
    use rand::Rng;
    use sia_core::rhp4::SECTOR_SIZE;
    use sia_core::types::v2::NetAddress;
    use std::io::Cursor;
    use std::time::Duration;

    use crate::mock::MockRHP4Transport;

    use super::*;

    const SLAB_SIZE: u64 = SECTOR_SIZE as u64 * 10; // 10 sectors per slab

    #[tokio::test]
    async fn test_upload_download_packed() {
        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let hosts = Hosts::new(Arc::new(MockRHP4Transport::new()));
        hosts.update(
            (0..60)
                .map(|_| Host {
                    public_key: PrivateKey::from_seed(&rand::random()).public_key(),
                    addresses: vec![NetAddress {
                        protocol: sia_core::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                })
                .collect(),
            true,
        );

        let uploader = Uploader::new(hosts.clone(), app_key.clone());
        let downloader = Downloader::new(hosts.clone(), app_key.clone());

        let input: Bytes = Bytes::from("Hello, world!");

        let mut packed_upload = uploader.upload_packed(UploadOptions::default());
        assert_eq!(packed_upload.remaining(), SLAB_SIZE);

        packed_upload
            .add(Cursor::new(input.clone()))
            .await
            .expect("add 1 to complete");
        packed_upload
            .add(Cursor::new(input.clone()))
            .await
            .expect("add 2 to complete");

        assert_eq!(
            packed_upload.remaining(),
            SLAB_SIZE - (input.len() * 2) as u64
        );

        let objects = packed_upload.finalize().await.expect("upload to finish");
        assert_eq!(objects.len(), 2);
        assert_ne!(objects[0].id(), objects[1].id()); // encryption keys should be different

        // Both objects should have 1 slab each, since the input is small enough to fit in a single slab.
        assert_eq!(objects[0].slabs().len(), 1);
        assert_eq!(objects[1].slabs().len(), 1);

        // obj 0 should be the first 13 bytes
        assert_eq!(objects[0].slabs()[0].offset, 0);
        assert_eq!(objects[0].size(), 13);

        // obj 1 should be the next 13 bytes
        assert_eq!(objects[1].slabs()[0].offset, 13);
        assert_eq!(objects[1].size(), 13);

        let mut output = BytesMut::zeroed(13);
        downloader
            .download(
                &mut Cursor::new(&mut output[..]),
                &objects[0],
                DownloadOptions::default(),
            )
            .await
            .expect("download to complete");

        assert_eq!(output.freeze(), input.clone());

        let mut output = BytesMut::zeroed(13);
        downloader
            .download(
                &mut Cursor::new(&mut output[..]),
                &objects[1],
                DownloadOptions::default(),
            )
            .await
            .expect("download to complete");

        assert_eq!(output.freeze(), input.clone());
    }

    #[tokio::test]
    async fn test_upload_download_packed_spanning() {
        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let hosts = Hosts::new(Arc::new(MockRHP4Transport::new()));
        hosts.update(
            (0..60)
                .map(|_| Host {
                    public_key: PrivateKey::from_seed(&rand::random()).public_key(),
                    addresses: vec![NetAddress {
                        protocol: sia_core::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                })
                .collect(),
            true,
        );

        let uploader = Uploader::new(hosts.clone(), app_key.clone());
        let downloader = Downloader::new(hosts.clone(), app_key.clone());

        let small_input = Bytes::from("Hello, world!");

        let mut large_input = BytesMut::zeroed(SLAB_SIZE as usize + 18); // 1 full slab + 18 bytes
        rand::rng().fill_bytes(&mut large_input);
        let large_input = large_input.freeze();

        let mut packed_upload = uploader.upload_packed(UploadOptions::default());
        packed_upload
            .add(Cursor::new(small_input.clone()))
            .await
            .expect("add 1 to complete");
        packed_upload
            .add(Cursor::new(large_input.clone()))
            .await
            .expect("add 2 to complete");

        let objects = packed_upload.finalize().await.expect("upload to finish");
        assert_eq!(objects.len(), 2);

        // The first object should have 1 slab
        assert_eq!(objects[0].slabs().len(), 1);
        assert_eq!(objects[1].slabs().len(), 2);

        // obj 0 should be the small input
        assert_eq!(objects[0].size(), 13);
        assert_eq!(objects[0].slabs()[0].offset, 0);
        assert_eq!(objects[0].slabs()[0].length, 13);

        // obj 1 should be the large input. The first slab starts at offset 13 so
        // its length must be SLAB_SIZE - 13. The second slab has the remaining bytes.
        assert_eq!(objects[1].size(), SLAB_SIZE + 18);
        assert_eq!(objects[1].slabs()[0].offset, 13);
        assert_eq!(objects[1].slabs()[0].length, (SLAB_SIZE - 13) as u32);
        assert_eq!(objects[1].slabs()[1].offset, 0);
        assert_eq!(objects[1].slabs()[1].length, 18 + 13);

        let mut output = BytesMut::zeroed(objects[0].size() as usize);
        downloader
            .download(
                &mut Cursor::new(&mut output[..]),
                &objects[0],
                DownloadOptions::default(),
            )
            .await
            .expect("download to complete");

        assert_eq!(output.freeze(), small_input);

        let mut output = BytesMut::zeroed(objects[1].size() as usize);
        downloader
            .download(
                &mut Cursor::new(&mut output[..]),
                &objects[1],
                DownloadOptions::default(),
            )
            .await
            .expect("download to complete");

        assert_eq!(output.freeze(), large_input);
    }

    #[tokio::test]
    async fn test_upload_download_packed_exact() {
        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let hosts = Hosts::new(Arc::new(MockRHP4Transport::new()));
        hosts.update(
            (0..60)
                .map(|_| Host {
                    public_key: PrivateKey::from_seed(&rand::random()).public_key(),
                    addresses: vec![NetAddress {
                        protocol: sia_core::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                })
                .collect(),
            true,
        );

        let uploader = Uploader::new(hosts.clone(), app_key.clone());
        let downloader = Downloader::new(hosts.clone(), app_key.clone());

        let mut exact_input = BytesMut::zeroed(SLAB_SIZE as usize); // 1 full slab
        rand::rng().fill_bytes(&mut exact_input);
        let exact_input = exact_input.freeze();

        let mut packed_upload = uploader.upload_packed(UploadOptions::default());
        packed_upload
            .add(Cursor::new(exact_input.clone()))
            .await
            .expect("add 1 to complete");

        let objects = packed_upload.finalize().await.expect("upload to finish");
        assert_eq!(objects.len(), 1);

        // The first object should have 1 slab, since it fits exactly
        assert_eq!(objects[0].slabs().len(), 1);
        // the first slab of obj[0] should be the full length. the second slab should be the remaining 18 bytes.
        assert_eq!(objects[0].size(), SLAB_SIZE);
        assert_eq!(objects[0].slabs()[0].offset, 0);
        assert_eq!(objects[0].slabs()[0].length, SLAB_SIZE as u32);

        let mut output = BytesMut::zeroed(objects[0].size() as usize);
        downloader
            .download(
                &mut Cursor::new(&mut output[..]),
                &objects[0],
                DownloadOptions::default(),
            )
            .await
            .expect("download to complete");

        assert_eq!(output.freeze(), exact_input);
    }

    #[tokio::test]
    async fn test_upload_download() {
        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let hosts = Hosts::new(Arc::new(MockRHP4Transport::new()));
        hosts.update(
            (0..60)
                .map(|_| Host {
                    public_key: PrivateKey::from_seed(&rand::random()).public_key(),
                    addresses: vec![NetAddress {
                        protocol: sia_core::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                })
                .collect(),
            true,
        );

        let uploader = Uploader::new(hosts.clone(), app_key.clone());
        let downloader = Downloader::new(hosts.clone(), app_key.clone());

        let input: Bytes = Bytes::from("Hello, world!");

        let object = uploader
            .upload(Cursor::new(input.clone()), UploadOptions::default())
            .await
            .expect("upload to complete");

        assert_eq!(object.slabs().len(), 1);
        assert_eq!(object.size(), 13);

        let mut output = BytesMut::zeroed(object.size() as usize);
        downloader
            .download(
                &mut Cursor::new(&mut output[..]),
                &object,
                DownloadOptions::default(),
            )
            .await
            .expect("download to complete");

        assert_eq!(output.freeze(), input.clone());

        let range = 7..13;
        let mut output = BytesMut::zeroed(range.end - range.start);
        downloader
            .download(
                &mut Cursor::new(&mut output[..]),
                &object,
                DownloadOptions {
                    offset: range.start as u64,
                    length: Some((range.end - range.start) as u64),
                    ..Default::default()
                },
            )
            .await
            .expect("download to complete");

        assert_eq!(output.freeze(), input.slice(range));
    }

    /// Port of Go SDK's client_test.go:TestDownload "ranges" subtest
    #[tokio::test]
    async fn test_download_ranges() {
        use sia_core::rhp4::SECTOR_SIZE;
        const SEGMENT_SIZE: u64 = 64; // leaf size

        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let hosts = Hosts::new(Arc::new(MockRHP4Transport::new()));
        hosts.update(
            (0..60)
                .map(|_| Host {
                    public_key: PrivateKey::from_seed(&rand::random()).public_key(),
                    addresses: vec![NetAddress {
                        protocol: sia_core::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                })
                .collect(),
            true,
        );

        let uploader = Uploader::new(hosts.clone(), app_key.clone());
        let downloader = Downloader::new(hosts.clone(), app_key.clone());

        // Use default 10 data shards, so slab_size = 10 * SECTOR_SIZE
        let slab_size = 10 * SECTOR_SIZE as u64;
        let data_size = slab_size * 3; // 3 slabs

        let mut data = BytesMut::zeroed(data_size as usize);
        rand::rng().fill_bytes(&mut data);
        let data = data.freeze();

        let object = uploader
            .upload(Cursor::new(data.clone()), UploadOptions::default())
            .await
            .expect("upload to complete");

        assert_eq!(object.slabs().len(), 3);

        // Test cases matching Go's TestDownload ranges
        let mut cases: Vec<(u64, u64)> = vec![
            (0, SECTOR_SIZE as u64),                              // first sector
            (SECTOR_SIZE as u64, SECTOR_SIZE as u64),             // second sector
            (SEGMENT_SIZE, SEGMENT_SIZE),                         // one leaf
            (SEGMENT_SIZE + 1, SEGMENT_SIZE / 2),                 // within a leaf
            (SEGMENT_SIZE + SEGMENT_SIZE / 2, SEGMENT_SIZE),      // across leaves
            (slab_size / 2, 2 * slab_size),                       // across slabs
            (data_size - SECTOR_SIZE as u64, SECTOR_SIZE as u64), // last sector
            (data_size - SEGMENT_SIZE, SEGMENT_SIZE),             // last leaf
            (data_size, 0),                                       // empty at end
        ];

        // Add 10 random ranges
        for _ in 0..10 {
            let offset = rand::random::<u64>() % (data_size - 1);
            let length = rand::random::<u64>() % (data_size - offset + 1);
            cases.push((offset, length));
        }

        for (offset, length) in cases {
            let mut output = BytesMut::zeroed(length as usize);
            downloader
                .download(
                    &mut Cursor::new(&mut output[..]),
                    &object,
                    DownloadOptions {
                        offset,
                        length: Some(length),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();

            assert_eq!(
                output.freeze(),
                data.slice(offset as usize..(offset + length) as usize),
                "data mismatch at offset={offset}, length={length}"
            );
        }
    }

    #[tokio::test]
    async fn test_download_slow_hosts() {
        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let mock_transport = Arc::new(MockRHP4Transport::new());
        let hosts = Hosts::new(mock_transport.clone());

        // Create 30 hosts and track their public keys
        let host_keys: Vec<_> = (0..30)
            .map(|_| PrivateKey::from_seed(&rand::random()).public_key())
            .collect();

        hosts.update(
            host_keys
                .iter()
                .map(|pk| Host {
                    public_key: *pk,
                    addresses: vec![NetAddress {
                        protocol: sia_core::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                })
                .collect(),
            true,
        );

        let uploader = Uploader::new(hosts.clone(), app_key.clone());
        let downloader = Downloader::new(hosts.clone(), app_key.clone());

        let input: Bytes = Bytes::from("Hello, world!");

        let object = uploader
            .upload(Cursor::new(input.clone()), UploadOptions::default())
            .await
            .expect("upload to complete");

        // make all hosts slow
        mock_transport.set_slow_hosts(
            host_keys.iter().take(30).copied(),
            tokio::time::Duration::from_secs(1),
        );

        let mut output = BytesMut::zeroed(object.size() as usize);
        downloader
            .download(
                &mut Cursor::new(&mut output[..]),
                &object,
                DownloadOptions::default(),
            )
            .await
            .expect("download to complete");

        assert_eq!(output.freeze(), input.clone());
    }

    #[tokio::test]
    async fn test_upload_no_hosts() {
        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let hosts = Hosts::new(Arc::new(MockRHP4Transport::new()));
        let uploader = Uploader::new(hosts.clone(), app_key.clone());

        let input: Bytes = Bytes::from("Hello, world!");

        let err = uploader
            .upload(Cursor::new(input.clone()), UploadOptions::default())
            .await
            .expect_err("upload to fail");

        match err {
            UploadError::QueueError(QueueError::InsufficientHosts) => (),
            _ => panic!(),
        }
    }

    /// Tests that upload succeeds even when some hosts are slow, as long as
    /// there are enough fast hosts to complete the upload.
    /// This mirrors Go's TestUpload "slow" subtest.
    #[tokio::test]
    async fn test_upload_slow_host() {
        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let mock_transport = Arc::new(MockRHP4Transport::new());
        let hosts = Hosts::new(mock_transport.clone());

        // Create 30 hosts and track their public keys
        let host_keys: Vec<_> = (0..30)
            .map(|_| PrivateKey::from_seed(&rand::random()).public_key())
            .collect();

        hosts.update(
            host_keys
                .iter()
                .map(|pk| Host {
                    public_key: *pk,
                    addresses: vec![NetAddress {
                        protocol: sia_core::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                })
                .collect(),
            true,
        );

        // make the 1st host slow
        mock_transport.set_slow_hosts(
            host_keys.iter().take(1).copied(),
            tokio::time::Duration::from_secs(2),
        );

        let uploader = Uploader::new(hosts.clone(), app_key.clone());

        let input: Bytes = Bytes::from("Hello, world!");

        let object = uploader
            .upload(Cursor::new(input.clone()), UploadOptions::default())
            .await
            .expect("upload should succeed with 1 slow host");

        assert_eq!(object.slabs().len(), 1);
    }

    // Upload should succeed even if all initial hosts are slow
    #[tokio::test]
    async fn test_upload_all_hosts_slow() {
        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let mock_transport = Arc::new(MockRHP4Transport::new());
        let hosts = Hosts::new(mock_transport.clone());

        // Create 30 hosts and track their public keys
        let host_keys: Vec<_> = (0..30)
            .map(|_| PrivateKey::from_seed(&rand::random()).public_key())
            .collect();

        hosts.update(
            host_keys
                .iter()
                .map(|pk| Host {
                    public_key: *pk,
                    addresses: vec![NetAddress {
                        protocol: sia_core::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                })
                .collect(),
            true,
        );

        // Make all hosts slow
        mock_transport.set_slow_hosts(host_keys.iter().take(30).copied(), Duration::from_secs(2));

        let uploader = Uploader::new(hosts.clone(), app_key.clone());

        let input: Bytes = Bytes::from("Hello, world!");

        let _ = uploader
            .upload(Cursor::new(input.clone()), UploadOptions::default())
            .await
            .expect("upload to succeed");
    }

    #[tokio::test]
    async fn test_upload_not_enough_hosts_good_for_upload() {
        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let hosts = Hosts::new(Arc::new(MockRHP4Transport::new()));
        // Create 30 hosts: 10 good for upload, 20 not good for upload
        let host_keys: Vec<_> = (0..30)
            .map(|_| PrivateKey::from_seed(&rand::random()).public_key())
            .collect();

        hosts.update(
            host_keys
                .iter()
                .enumerate()
                .map(|(i, pk)| Host {
                    public_key: *pk,
                    addresses: vec![NetAddress {
                        protocol: sia_core::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: i < 10,
                })
                .collect(),
            true,
        );

        let uploader = Uploader::new(hosts.clone(), app_key.clone());

        let input: Bytes = Bytes::from("Hello, world!");

        let err = uploader
            .upload(Cursor::new(input.clone()), UploadOptions::default())
            .await
            .expect_err("upload to fail");

        match err {
            UploadError::QueueError(QueueError::InsufficientHosts) => (),
            _ => panic!(),
        }
    }
}
