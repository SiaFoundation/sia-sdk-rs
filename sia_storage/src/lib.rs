//! A Rust SDK for storing and retrieving data on the Sia decentralized storage network.
//!
//! [Sia](https://sia.tech) is a decentralized cloud storage platform where data is
//! stored across a global network of independent hosts. Storage contracts are
//! enforced by the Sia blockchain, so no single party controls your data. Compared
//! to centralized providers, Sia offers lower costs, stronger privacy (data is
//! client-side encrypted by default), and censorship resistance.
//!
//! This crate provides a high-level interface for interacting with Sia through an
//! indexer service. Data is automatically erasure-coded, encrypted, and distributed
//! across hosts on the network.
//!
//! # Getting started
//!
//! Define your [AppMetadata] as a constant. The [AppID] is used to derive the
//! user's encryption keys -- if it changes, previously stored data becomes
//! inaccessible. Generate it once (e.g. with a random hash) and never change it.
//!
//! Use [Builder] to connect to an indexer and obtain an [SDK] instance. There are
//! two paths:
//!
//! - **First time**: Call [Builder::request_connection] to start the approval flow,
//!   then [Builder::wait_for_approval] once the user has approved, and finally
//!   [Builder::register] to complete setup. This derives an [AppKey] from the
//!   user's recovery phrase.
//! - **Returning**: Call [Builder::connected] with a previously exported [AppKey].
//!
//! Once you have an [SDK], use it to upload, download, and manage objects:
//!
//! ```ignore
//! // Upload
//! let object = sdk.upload(Object::default(), reader, UploadOptions::default()).await?;
//! sdk.pin_object(&object).await?;
//!
//! // Download
//! sdk.download(&mut writer, &object, DownloadOptions::default()).await?;
//! ```
//!
//! # Key management
//!
//! The [AppKey] grants full access to a user's data. After connecting, retrieve it
//! with [SDK::app_key], then persist it using [AppKey::export] and restore it with
//! [AppKey::import] so users don't need to re-approve on every launch.

#[macro_use]
mod compat;

pub(crate) use compat::{task, time};

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

#[cfg(any(test, feature = "mock"))]
pub mod mock;

use std::sync::Arc;

use log::{debug, warn};
use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::app_client::SlabPinParams;
use crate::download::download_object;
pub use crate::hosts::Host;
use crate::hosts::Hosts;
use crate::rhp4::{Client, HostEndpoint};
use crate::task::AbortOnDropHandle;
use crate::time::Duration;
use crate::upload::Uploader;
pub use chrono::{DateTime, Utc};
pub use reqwest::{IntoUrl, Url};
#[doc(hidden)]
pub use sia_core::macros::decode_hex_256;
pub use sia_core::seed::SeedError;
pub use sia_core::signing::{PrivateKey, PublicKey, Signature};
pub use sia_core::types::{Currency, Hash256};
pub use sia_core::types::v2::Protocol;

pub use app_client::Error as AppApiError;
pub use builder::{
    ApprovedState, Builder, BuilderError, DisconnectedState, RequestingApprovalState,
};
pub use download::{DownloadError, DownloadOptions};
pub use encryption::EncryptionKey;
pub use hosts::{QueueError, RPCError};
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
    /// The unique identifier of the application.
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

/// An application key used for authentication with the indexd service, derived
/// from the user's mnemonic and a shared secret from the approval process.
///
/// Use [AppKey::export] to export the key and store it for future connections.
///
/// # Security
/// This exported key is very sensitive and should be stored securely. Anyone with access
/// to this key can authenticate as the user and access their data and permissions. It is recommended
/// to store this key in a secure vault or encrypted storage.
#[derive(Clone)]
pub struct AppKey(pub(crate) PrivateKey);

impl AppKey {
    /// Imports an existing app key from a seed previously exported using [AppKey::export].
    pub fn import(buf: [u8; 32]) -> Self {
        AppKey(PrivateKey::from_seed(&buf))
    }

    /// Exports the app key. This can be stored securely and used for future connections.
    /// The exported key is a 32-byte array that can be used to reconstruct the app key using [AppKey::import].
    ///
    /// # Security
    /// This exported key is very sensitive and should be stored securely. Anyone with access
    /// to this key can authenticate as the user and access their data and permissions. It is recommended
    /// to store this key in a secure vault or encrypted storage.
    pub fn export(&self) -> [u8; 32] {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.0.as_ref()[..32]);
        arr
    }

    /// Signs a message using the app key
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.0.sign(message)
    }

    /// Returns the public key corresponding to this app key
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }
}

/// A cursor for paginating through object events returned by [SDK::object_events].
pub struct ObjectsCursor {
    /// Only return events after this timestamp.
    pub after: DateTime<Utc>,
    /// Only return events after this object ID.
    pub id: Hash256,
}

/// A host's estimated geographic location represented as latitude and longitude coordinates.
#[derive(Debug, Clone, Copy, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoLocation {
    /// The latitude coordinate.
    pub latitude: f64,
    /// The longitude coordinate.
    pub longitude: f64,
}

impl Serialize for GeoLocation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let formatted = format!("({:.6},{:.6})", self.latitude, self.longitude);
        serializer.serialize_str(&formatted)
    }
}

/// Parameters for filtering hosts returned by [SDK::hosts].
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct HostQuery {
    /// Sort hosts by proximity to this location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<GeoLocation>,
    /// The number of hosts to skip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// The maximum number of hosts to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Filter hosts by supported protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    /// Filter hosts by country code (ISO 3166-1 alpha-2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// Metadata about a registered application on the indexer.
#[derive(Debug, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct App {
    /// The unique identifier of the application.
    pub id: Hash256,
    /// The human-readable name of the application.
    pub name: String,
    /// A brief description of the application.
    pub description: String,
    /// An optional URL pointing to the application's logo.
    pub logo_url: Option<String>,
    /// An optional URL where the application can be accessed.
    pub service_url: Option<String>,
}

/// Information about the user's account on the indexer.
#[derive(Debug, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    /// The public key associated with the account.
    pub account_key: PublicKey,
    /// The maximum amount of data that can be pinned to the indexer for this account.
    pub max_pinned_data: u64,
    /// Remaining amount of data in bytes that can still be pinned, after applying both the account limit and current quota limit.
    pub remaining_storage: u64,
    /// The amount of data currently pinned to the indexer for this account. This
    /// counts towards max pinned data.
    pub pinned_data: u64,
    /// The amount of data after erasure encoding. This is the actual amount of data on the network.
    pub pinned_size: u64,
    /// Whether the account is ready to be used. After registering an app, the account may not be
    /// immediately ready as the indexer needs to process the registration and sync with the network.
    /// The account will become ready once it has propagated on the network.
    pub ready: bool,
    /// The application registered to this account.
    pub app: App,
    /// The last time the account was used.
    pub last_used: DateTime<Utc>,
}

/// Errors that can occur when using the SDK.
#[derive(Error, Debug)]
pub enum Error {
    /// An error from the indexer API.
    #[error("app error: {0}")]
    App(String),

    /// An error during upload.
    #[error("upload error: {0}")]
    Upload(#[from] UploadError),

    /// An error during download.
    #[error("download error: {0}")]
    Download(#[from] DownloadError),

    /// A TLS connection error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// An error opening or sealing an object.
    #[error("sealed object: {0}")]
    SealedObject(#[from] SealedObjectError),
}

/// The main interface with interacting with the Sia storage network. It provides methods for uploading and downloading objects, as well as managing hosts and account information.
#[derive(Clone)]
pub struct SDK {
    app_key: Arc<AppKey>,
    api_client: app_client::Client,
    hosts: Hosts<Client>,
    uploader: Uploader<Client>,
    _refresh_task: Arc<AbortOnDropHandle<()>>,
}

impl SDK {
    async fn refresh_hosts(
        app_key: &AppKey,
        api_client: &app_client::Client,
        hosts: &Hosts<Client>,
    ) -> Result<(), app_client::Error> {
        const PAGE_SIZE: usize = 100;
        let mut all_hosts = Vec::new();
        for i in (0..).step_by(PAGE_SIZE) {
            let page = api_client
                .hosts(
                    &app_key.0,
                    HostQuery {
                        offset: Some(i),
                        limit: Some(PAGE_SIZE as u64),
                        ..Default::default()
                    },
                )
                .await?;
            let done = page.len() < PAGE_SIZE;
            all_hosts.extend(page);
            if done {
                break;
            }
        }

        let good_for_upload: Vec<_> = all_hosts
            .iter()
            .filter(|h| h.good_for_upload)
            .map(|h| HostEndpoint {
                public_key: h.public_key,
                addresses: h.addresses.clone(),
            })
            .collect();

        debug!(
            "Refreshed hosts: total {}, good for upload {}",
            all_hosts.len(),
            good_for_upload.len()
        );
        hosts.update(all_hosts, true);
        let hosts = hosts.clone();
        maybe_spawn!(async move {
            hosts.warm_connections(good_for_upload).await;
        });
        Ok(())
    }

    /// Creates a new SDK instance.
    async fn new(
        api_client: app_client::Client,
        app_key: Arc<AppKey>,
    ) -> Result<Self, BuilderError> {
        let hosts = Hosts::new(Client::new());
        Self::refresh_hosts(&app_key, &api_client, &hosts).await?;
        let uploader = Uploader::new(hosts.clone(), app_key.clone());
        let refresh_task = Self::spawn_refresh_task(
            app_key.clone(),
            api_client.clone(),
            hosts.clone(),
            Duration::from_secs(10 * 60),
        );
        Ok(Self {
            app_key,
            api_client,
            hosts,
            uploader,
            _refresh_task: Arc::new(refresh_task),
        })
    }

    /// Spawns a background task that refreshes the host list at the given interval.
    fn spawn_refresh_task(
        app_key: Arc<AppKey>,
        api_client: app_client::Client,
        hosts: Hosts<Client>,
        interval: Duration,
    ) -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(maybe_spawn!(async move {
            loop {
                crate::time::sleep(interval).await;
                if let Err(err) = Self::refresh_hosts(&app_key, &api_client, &hosts).await {
                    warn!("failed to refresh hosts: {err}");
                }
            }
        }))
    }

    /// Returns the application key used by the SDK.
    ///
    /// This should be kept secret and secure. Applications
    /// should store it safely.
    pub fn app_key(&self) -> &AppKey {
        &self.app_key
    }

    /// Reads until EOF and uploads all slabs. The data will be erasure coded,
    /// encrypted, and uploaded.
    ///
    /// Pass [Object::default] for new uploads. To resume a previous upload,
    /// pass the object returned from the earlier call. Appending data changes
    /// an object's ID. It must be re-pinned afterward and any references to
    /// the previous ID must be updated.
    ///
    /// # Arguments
    /// * `object` - The object to upload into. Use `Object::default()` for new uploads.
    /// * `r` - The reader to read the data from. It will be read until EOF.
    /// * `options` - The [UploadOptions] to use for the upload.
    ///
    /// # Returns
    /// The object containing the metadata needed to download. The caller must
    /// pin the object to the indexer after uploading.
    pub async fn upload<R: AsyncRead + Unpin + Send + 'static>(
        &self,
        object: Object,
        reader: R,
        options: UploadOptions,
    ) -> Result<Object, UploadError> {
        self.uploader.upload(object, reader, options).await
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
        download_object(self.hosts.clone(), self.app_key.clone(), w, object, options).await
    }

    /// Retrieves a list of hosts from the indexer matching the provided query
    /// that can be used for uploading and downloading data.
    ///
    /// # Arguments
    /// * `query` - Filtering criteria to select hosts.
    pub async fn hosts(&self, query: HostQuery) -> Result<Vec<Host>, Error> {
        self.api_client
            .hosts(&self.app_key.0, query)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Queries a host for the account's remaining balance.
    pub async fn host_account_balance(
        &self,
        host_key: PublicKey,
    ) -> Result<Currency, Error> {
        self.hosts
            .account_balance(host_key, &self.app_key.0)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Retrieves account information from the indexer.
    pub async fn account(&self) -> Result<Account, Error> {
        self.api_client
            .account(&self.app_key.0)
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
            .object(&self.app_key.0, key)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        let obj = sealed.open(self.app_key.as_ref())?;
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
            .objects(&self.app_key.0, cursor, limit)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        let objs = events
            .into_iter()
            .map(|event| {
                let object = match event.object {
                    Some(sealed) => Some(sealed.open(self.app_key.as_ref())?),
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
            .prune_slabs(&self.app_key.0)
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
        let sealed = object.seal(self.app_key.as_ref());
        self.api_client
            .pin_object(&self.app_key.0, &sealed)
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
            .delete_object(&self.app_key.0, id)
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
            .shared_object_url(&self.app_key.0, object, valid_until)
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
            .pin_slabs(&self.app_key.0, slabs)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        self.api_client
            .pin_object(&self.app_key.0, &object.seal(self.app_key.as_ref()))
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        Ok(())
    }

    /// Retrieves a pinned slab from the indexer by its id.
    pub async fn slab(&self, id: &Hash256) -> Result<PinnedSlab, Error> {
        self.api_client
            .slab(&self.app_key.0, id)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Reads a raw sector from a host. Used for migration and repair.
    pub async fn read_sector(
        &self,
        host_key: PublicKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<bytes::Bytes, Error> {
        self.hosts
            .read_sector(
                host_key,
                &self.app_key.0,
                root,
                offset,
                length,
                Duration::from_secs(60),
            )
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Writes a raw sector to a host. Used for migration and repair.
    /// Returns the sector's Merkle root.
    pub async fn write_sector(
        &self,
        host_key: PublicKey,
        sector: bytes::Bytes,
    ) -> Result<Hash256, Error> {
        self.hosts
            .write_sector(
                host_key,
                &self.app_key.0,
                sector,
                Duration::from_secs(120),
            )
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }
}

/// Estimates the on-network encoded size of data after erasure coding.
pub fn encoded_size(data_size: u64, data_shards: u8, parity_shards: u8) -> u64 {
    let total_shards = data_shards as u64 + parity_shards as u64;
    let sector_size = sia_core::rhp4::SECTOR_SIZE as u64;
    let slab_size = total_shards * sector_size;
    let slabs = data_size.div_ceil(data_shards as u64 * sector_size);
    slabs * slab_size
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
    use crate::compat::run_local;
    use crate::hosts::QueueError;
    use bytes::{Bytes, BytesMut};
    use sia_core::rhp4::SECTOR_SIZE;
    use sia_core::signing::PrivateKey;
    use sia_core::types::v2::NetAddress;
    use std::io::Cursor;

    use crate::mock::MockRHP4Transport;
    use crate::time::Duration;

    use super::*;

    const SLAB_SIZE: u64 = SECTOR_SIZE as u64 * 10; // 10 sectors per slab

    fn random_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        seed
    }

    fn random_bytes(buf: &mut [u8]) {
        getrandom::fill(buf).unwrap();
    }

    fn random_u64() -> u64 {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).unwrap();
        u64::from_le_bytes(bytes)
    }

    cross_target_tests! {
        async fn test_upload_download_packed() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(MockRHP4Transport::new());
            hosts.update(
                (0..60)
                    .map(|_| Host {
                        public_key: PrivateKey::from_seed(&random_seed()).public_key(),
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
            download_object(
                hosts.clone(),
                app_key.clone(),
                &mut Cursor::new(&mut output[..]),
                    &objects[0],
                    DownloadOptions::default(),
                )
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), input.clone());

            let mut output = BytesMut::zeroed(13);
            download_object(
                hosts.clone(),
                app_key.clone(),
                &mut Cursor::new(&mut output[..]),
                    &objects[1],
                    DownloadOptions::default(),
                )
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), input.clone());
        }).await }

        async fn test_upload_download_packed_spanning() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(MockRHP4Transport::new());
            hosts.update(
                (0..60)
                    .map(|_| Host {
                        public_key: PrivateKey::from_seed(&random_seed()).public_key(),
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


            let small_input = Bytes::from("Hello, world!");

            let mut large_input = BytesMut::zeroed(SLAB_SIZE as usize + 18); // 1 full slab + 18 bytes
            random_bytes(&mut large_input);
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
            download_object(
                hosts.clone(),
                app_key.clone(),
                &mut Cursor::new(&mut output[..]),
                    &objects[0],
                    DownloadOptions::default(),
                )
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), small_input);

            let mut output = BytesMut::zeroed(objects[1].size() as usize);
            download_object(
                hosts.clone(),
                app_key.clone(),
                &mut Cursor::new(&mut output[..]),
                    &objects[1],
                    DownloadOptions::default(),
                )
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), large_input);
        }).await }

    async fn test_upload_download_packed_exact() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(MockRHP4Transport::new());
            hosts.update(
                (0..60)
                    .map(|_| Host {
                        public_key: PrivateKey::from_seed(&random_seed()).public_key(),
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


            let mut exact_input = BytesMut::zeroed(SLAB_SIZE as usize); // 1 full slab
            random_bytes(&mut exact_input);
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
            download_object(
                hosts.clone(),
                app_key.clone(),
                &mut Cursor::new(&mut output[..]),
                    &objects[0],
                    DownloadOptions::default(),
                )
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), exact_input);
        }).await }

    async fn test_upload_download() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(MockRHP4Transport::new());
            hosts.update(
                (0..60)
                    .map(|_| Host {
                        public_key: PrivateKey::from_seed(&random_seed()).public_key(),
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


            let input: Bytes = Bytes::from("Hello, world!");

            let object = uploader
                .upload(Object::default(), Cursor::new(input.clone()), UploadOptions::default())
                .await
                .expect("upload to complete");

            assert_eq!(object.slabs().len(), 1);
            assert_eq!(object.size(), 13);

            let mut output = BytesMut::zeroed(object.size() as usize);
            download_object(
                hosts.clone(),
                app_key.clone(),
                &mut Cursor::new(&mut output[..]),
                    &object,
                    DownloadOptions::default(),
                )
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), input.clone());

            let range = 7..13;
            let mut output = BytesMut::zeroed(range.end - range.start);
            download_object(
                hosts.clone(),
                app_key.clone(),
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
        }).await }

        async fn test_upload_append() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(MockRHP4Transport::new());
            hosts.update(
                (0..60)
                    .map(|_| Host {
                        public_key: PrivateKey::from_seed(&random_seed()).public_key(),
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

            let part1 = Bytes::from("Hello, ");
            let part2 = Bytes::from("world!");
            let expected = Bytes::from("Hello, world!");

            // first upload
            let object = uploader
                .upload(Object::default(), Cursor::new(part1.clone()), UploadOptions::default())
                .await
                .expect("first upload to complete");
            assert_eq!(object.size(), part1.len() as u64);

            // resume with second part
            let object = uploader
                .upload(object, Cursor::new(part2.clone()), UploadOptions::default())
                .await
                .expect("second upload to complete");
            assert_eq!(object.size(), expected.len() as u64);

            // download the full object and verify concatenation
            let mut output = BytesMut::zeroed(expected.len());
            download_object(
                hosts.clone(),
                app_key.clone(),
                &mut Cursor::new(&mut output[..]),
                &object,
                DownloadOptions::default(),
            )
            .await
            .expect("download to complete");

            assert_eq!(output.freeze(), expected);
        }).await }

        /// Port of Go SDK's client_test.go:TestDownload "ranges" subtest
    async fn test_download_ranges() { run_local(async {
            use sia_core::rhp4::SECTOR_SIZE;
            const SEGMENT_SIZE: u64 = 64; // leaf size

            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(MockRHP4Transport::new());
            hosts.update(
                (0..60)
                    .map(|_| Host {
                        public_key: PrivateKey::from_seed(&random_seed()).public_key(),
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


            // Use default 10 data shards, so slab_size = 10 * SECTOR_SIZE
            let slab_size = 10 * SECTOR_SIZE as u64;
            let data_size = slab_size * 3; // 3 slabs

            let mut data = BytesMut::zeroed(data_size as usize);
            random_bytes(&mut data);
            let data = data.freeze();

            let object = uploader
                .upload(Object::default(), Cursor::new(data.clone()), UploadOptions::default())
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
                (data_size - 100, 200),                               // past end
                (data_size, 0),                                       // empty at end
                (data_size + 100, 0),                                 // empty past end
            ];

            // Add 10 random ranges
            for _ in 0..10 {
                let offset = random_u64() % (data_size - 1);
                let length = random_u64() % (data_size - offset + 1);
                cases.push((offset, length));
            }

            for (offset, length) in cases {
                let mut output = Vec::with_capacity(length as usize);
                download_object(
                    hosts.clone(),
                    app_key.clone(),
                    &mut output,
                    &object,
                    DownloadOptions {
                        offset,
                        length: Some(length),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();

                let clamped_length = if offset >= data_size {
                    0
                } else {
                    length.min(data_size - offset) as usize
                };
                let clamped_offset = offset.min(data_size) as usize;
                let clamped_range = clamped_offset..(clamped_offset + clamped_length);

                assert_eq!(
                    Bytes::from(output),
                    data.slice(clamped_range),
                    "data mismatch at offset={offset}, length={length}"
                );
            }
        }).await }

    async fn test_download_slow_hosts() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let mock_transport = MockRHP4Transport::new();
            let hosts = Hosts::new(mock_transport.clone());

            // Create 30 hosts and track their public keys
            let host_keys: Vec<_> = (0..30)
                .map(|_| PrivateKey::from_seed(&random_seed()).public_key())
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


            let input: Bytes = Bytes::from("Hello, world!");

            let object = uploader
                .upload(Object::default(), Cursor::new(input.clone()), UploadOptions::default())
                .await
                .expect("upload to complete");

            // make all hosts slow
            mock_transport.set_slow_hosts(
                host_keys.iter().take(30).copied(),
                Duration::from_secs(1),
            );

            let mut output = BytesMut::zeroed(object.size() as usize);
            download_object(
                hosts.clone(),
                app_key.clone(),
                &mut Cursor::new(&mut output[..]),
                    &object,
                    DownloadOptions::default(),
                )
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), input.clone());
        }).await }

    async fn test_upload_no_hosts() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(MockRHP4Transport::new());
            let uploader = Uploader::new(hosts.clone(), app_key.clone());

            let input: Bytes = Bytes::from("Hello, world!");

            let err = uploader
                .upload(Object::default(), Cursor::new(input.clone()), UploadOptions::default())
                .await
                .expect_err("upload to fail");

            match err {
                UploadError::QueueError(QueueError::InsufficientHosts) => (),
                _ => panic!(),
            }
        }).await }

        /// Tests that upload succeeds even when some hosts are slow, as long as
        /// there are enough fast hosts to complete the upload.
        /// This mirrors Go's TestUpload "slow" subtest.
    async fn test_upload_slow_host() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let mock_transport = MockRHP4Transport::new();
            let hosts = Hosts::new(mock_transport.clone());

            // Create 30 hosts and track their public keys
            let host_keys: Vec<_> = (0..30)
                .map(|_| PrivateKey::from_seed(&random_seed()).public_key())
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
                Duration::from_secs(2),
            );

            let uploader = Uploader::new(hosts.clone(), app_key.clone());

            let input: Bytes = Bytes::from("Hello, world!");

            let object = uploader
                .upload(Object::default(), Cursor::new(input.clone()), UploadOptions::default())
                .await
                .expect("upload should succeed with 1 slow host");

            assert_eq!(object.slabs().len(), 1);
        }).await }

        // Upload should succeed even if all initial hosts are slow
    async fn test_upload_all_hosts_slow() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let mock_transport = MockRHP4Transport::new();
            let hosts = Hosts::new(mock_transport.clone());

            // Create 30 hosts and track their public keys
            let host_keys: Vec<_> = (0..30)
                .map(|_| PrivateKey::from_seed(&random_seed()).public_key())
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
                .upload(Object::default(), Cursor::new(input.clone()), UploadOptions::default())
                .await
                .expect("upload to succeed");
        }).await }

    async fn test_upload_not_enough_hosts_good_for_upload() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(MockRHP4Transport::new());
            // Create 30 hosts: 10 good for upload, 20 not good for upload
            let host_keys: Vec<_> = (0..30)
                .map(|_| PrivateKey::from_seed(&random_seed()).public_key())
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
                .upload(Object::default(), Cursor::new(input.clone()), UploadOptions::default())
                .await
                .expect_err("upload to fail");

            match err {
                UploadError::QueueError(QueueError::InsufficientHosts) => (),
                _ => panic!(),
            }
        }).await }
        }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_refresh_task_periodic_and_abort() {
        use httptest::http::{Response, StatusCode};
        use httptest::matchers::*;
        use httptest::{Expectation, Server};

        const INTERVAL: Duration = Duration::from_millis(200);
        const WAIT: Duration = Duration::from_millis(500);

        // API returns hosts with good_for_upload=false so warm_connections is a no-op
        let hosts: Vec<Host> = (0..3)
            .map(|_| Host {
                public_key: PrivateKey::from_seed(&random_seed()).public_key(),
                addresses: vec![NetAddress {
                    protocol: sia_core::types::v2::Protocol::QUIC,
                    address: "localhost:1234".to_string(),
                }],
                country_code: "US".to_string(),
                latitude: 0.0,
                longitude: 0.0,
                good_for_upload: false,
            })
            .collect();
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/hosts"))
                .times(..)
                .respond_with(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(serde_json::to_string(&hosts).unwrap())
                        .unwrap(),
                ),
        );

        let app_key = Arc::new(AppKey::import(random_seed()));
        let client = crate::app_client::Client::new(server.url("/").to_string()).unwrap();
        let hosts = Hosts::new(crate::rhp4::Client::new());

        // helper: seed one good-for-upload host so available_for_upload() == 1
        let add_upload_host = |hosts: &Hosts<crate::rhp4::Client>| {
            hosts.update(
                vec![Host {
                    public_key: PrivateKey::from_seed(&random_seed()).public_key(),
                    addresses: vec![],
                    country_code: String::new(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                }],
                false,
            );
        };

        // verify initial refresh replaces hosts
        add_upload_host(&hosts);
        assert_eq!(hosts.available_for_upload(), 1);
        SDK::refresh_hosts(&app_key, &client, &hosts).await.unwrap();
        assert_eq!(
            hosts.available_for_upload(),
            0,
            "initial refresh should clear upload hosts"
        );

        // spawn the periodic refresh task with a short interval
        add_upload_host(&hosts);
        assert_eq!(hosts.available_for_upload(), 1);
        let handle =
            SDK::spawn_refresh_task(app_key.clone(), client.clone(), hosts.clone(), INTERVAL);

        // wait for periodic refresh to run
        tokio::time::sleep(WAIT).await;
        assert_eq!(
            hosts.available_for_upload(),
            0,
            "periodic refresh should have run"
        );

        // verify it refreshes again
        add_upload_host(&hosts);
        tokio::time::sleep(WAIT).await;
        assert_eq!(
            hosts.available_for_upload(),
            0,
            "second periodic refresh should have run"
        );

        // drop handle to abort the task
        drop(handle);
        add_upload_host(&hosts);
        assert_eq!(hosts.available_for_upload(), 1);

        // wait past the interval - should NOT refresh (task aborted)
        tokio::time::sleep(WAIT).await;
        assert_eq!(
            hosts.available_for_upload(),
            1,
            "refresh task should be aborted"
        );
    }
}
