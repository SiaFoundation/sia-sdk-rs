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
//! Use [Builder] to connect to an indexer and obtain an [Sdk] instance. There are
//! two paths:
//!
//! - **First time**: Call [Builder::request_connection] to start the approval flow,
//!   then [Builder::wait_for_approval] once the user has approved, and finally
//!   [Builder::register] to complete setup. This derives an [AppKey] from the
//!   user's recovery phrase.
//! - **Returning**: Call [Builder::connected] with a previously exported [AppKey].
//!
//! Once you have an [Sdk], use it to upload, download, and manage objects:
//!
//! ```ignore
//! // Upload
//! let object = sdk.upload(Object::default(), reader, UploadOptions::default()).await?;
//! sdk.pin_object(&object).await?;
//!
//! // Download
//! let mut reader = sdk.download(&object, DownloadOptions::default())?;
//! tokio::io::copy(&mut reader, &mut writer).await?;
//! ```
//!
//! # Key management
//!
//! The [AppKey] grants full access to a user's data. After connecting, retrieve it
//! with [Sdk::app_key], then persist it using [AppKey::export] and restore it with
//! [AppKey::import] so users don't need to re-approve on every launch.

#[macro_use]
mod compat;

pub(crate) use compat::{task, time};
use sia_core::rhp4::SECTOR_SIZE;
use sia_core::signing::PrivateKey;

mod app_client;
mod builder;
mod download;
mod encryption;
mod erasure_coding;
mod hosts;
mod object_encryption;
mod rhp4;
mod sdk;
mod slabs;
mod upload;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

pub use sdk::{Error, Sdk};

use std::sync::Arc;

use serde::Serialize;

pub use crate::hosts::Host;
use crate::hosts::Hosts;

use crate::time::Duration;
pub use chrono::{DateTime, Utc};
pub use reqwest::{IntoUrl, Url};
#[doc(hidden)]
pub use sia_core::macros::decode_hex_256;
pub use sia_core::seed::SeedError;
pub use sia_core::signing::{PublicKey, Signature};
pub use sia_core::types::Hash256;
pub use sia_core::types::v2::Protocol;

pub use app_client::Error as AppApiError;
pub use builder::{
    ApprovedState, Builder, BuilderError, DisconnectedState, RequestingApprovalState,
};
pub use download::{Download, DownloadError};
pub use encryption::EncryptionKey;
pub use hosts::{QueueError, RPCError};
pub use slabs::{Object, ObjectEvent, PinnedSlab, SealedObject, SealedObjectError, Sector, Slab};
pub use upload::{PackedUpload, UploadError};

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

/// A cursor for paginating through object events returned by [Sdk::object_events].
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

/// Parameters for filtering hosts returned by [Sdk::hosts].
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
#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq)]
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
#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq)]
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

#[cfg(not(target_arch = "wasm32"))]
pub type ShardProgressCallback = Arc<dyn Fn(ShardProgress) + Send + Sync + 'static>;

#[cfg(target_arch = "wasm32")]
pub type ShardProgressCallback = Arc<dyn Fn(ShardProgress) + 'static>;

/// Information about a successfully uploaded or downloaded shard, used for progress reporting.
pub struct ShardProgress {
    pub host_key: PublicKey,
    pub shard_size: usize,
    pub shard_index: usize,
    pub slab_index: usize,
    pub elapsed: Duration,
}

/// Options for configuring a download.
pub struct DownloadOptions {
    /// Maximum number of concurrent chunk downloads. Defaults to 80.
    pub max_inflight: usize,
    /// Byte offset to start downloading from.
    pub offset: u64,
    /// Number of bytes to download. If `None`, downloads the entire object.
    pub length: Option<u64>,

    pub shard_downloaded: Option<ShardProgressCallback>,
}

impl DownloadOptions {
    /// Configures a callback to receive progress updates for each downloaded shard.
    #[cfg(target_arch = "wasm32")]
    pub fn on_shard_downloaded<F>(mut self, callback: F) -> Self
    where
        F: Fn(ShardProgress) + 'static,
    {
        self.shard_downloaded = Some(Arc::new(callback));
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn on_shard_downloaded<F>(mut self, callback: F) -> Self
    where
        F: Fn(ShardProgress) + Send + Sync + 'static,
    {
        self.shard_downloaded = Some(Arc::new(callback));
        self
    }
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            max_inflight: 270, // ~20 MiB in memory
            offset: 0,
            length: None,
            shard_downloaded: None,
        }
    }
}

/// Options for configuring an upload.
pub struct UploadOptions {
    /// The number of data shards per slab. Defaults to 10.
    pub data_shards: u8,
    /// The number of parity shards per slab. Defaults to 20.
    pub parity_shards: u8,
    /// The maximum number of concurrent shard uploads. Defaults to 15.
    pub max_inflight: usize,

    /// Optional callback to receive progress updates for each uploaded shard.
    pub shard_uploaded: Option<ShardProgressCallback>,
}

impl UploadOptions {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn on_shard_uploaded<F>(mut self, callback: F) -> Self
    where
        F: Fn(ShardProgress) + Send + Sync + 'static,
    {
        self.shard_uploaded = Some(Arc::new(callback));
        self
    }

    #[cfg(target_arch = "wasm32")]
    pub fn on_shard_uploaded<F>(mut self, callback: F) -> Self
    where
        F: Fn(ShardProgress) + 'static,
    {
        self.shard_uploaded = Some(Arc::new(callback));
        self
    }
}

impl UploadOptions {
    /// Returns the optimal data size per slab in bytes.
    pub fn optimal_data_size(&self) -> usize {
        SECTOR_SIZE * self.data_shards as usize
    }

    /// Returns the total slab size including parity shards in bytes.
    pub fn slab_size(&self) -> usize {
        SECTOR_SIZE * (self.data_shards as usize + self.parity_shards as usize)
    }

    /// Validates the upload options and erasure coding parameters to ensure
    /// sufficient durability.
    ///
    /// This checks that the redundancy ratio is between 1.5x and 4x and that
    /// the probability of recovering the original data meets a minimum threshold
    /// of 99.99%.
    pub fn validate(&self) -> Result<(), UploadError> {
        const MIN_REDUNDANCY: f64 = 1.5;
        const MAX_REDUNDANCY: f64 = 4.0;
        const RECOVERY_PROBABILITY: f64 = 0.75;
        const MIN_RECOVERY_PROBABILITY: f64 = 99.99;
        const MAX_TOTAL_SHARDS: u16 = 256;

        if self.max_inflight == 0 {
            return Err(UploadError::InvalidOptions(
                "max_inflight must be greater than 0".into(),
            ));
        }

        let data_shards = self.data_shards as u16;
        let parity_shards = self.parity_shards as u16;
        let total_shards = data_shards + parity_shards;

        if data_shards == 0 {
            return Err(UploadError::InvalidOptions(
                "data shards cannot be zero".into(),
            ));
        } else if parity_shards == 0 {
            return Err(UploadError::InvalidOptions(
                "parity shards cannot be zero".into(),
            ));
        } else if total_shards > MAX_TOTAL_SHARDS {
            return Err(UploadError::InvalidOptions(format!(
                "total shards {total_shards} exceeds maximum of {MAX_TOTAL_SHARDS}"
            )));
        }

        let redundancy = total_shards as f64 / data_shards as f64;
        if redundancy < MIN_REDUNDANCY {
            return Err(UploadError::InvalidOptions(format!(
                "redundancy of {redundancy:.2} is too low"
            )));
        } else if redundancy > MAX_REDUNDANCY {
            return Err(UploadError::InvalidOptions(format!(
                "redundancy of {redundancy:.2} is too high"
            )));
        }

        // Calculate recovery probability using the binomial CDF.
        // P(X >= data_shards) where X ~ Binomial(total_shards, RECOVERY_PROBABILITY)
        let q = 1.0 - RECOVERY_PROBABILITY;
        let mut term = q.powi(total_shards as i32);
        for i in 0..data_shards {
            term *= (total_shards - i) as f64 / (i + 1) as f64 * (RECOVERY_PROBABILITY / q);
        }
        let mut sum = term;
        for i in data_shards..total_shards {
            term *= (total_shards - i) as f64 / (i + 1) as f64 * (RECOVERY_PROBABILITY / q);
            sum += term;
        }
        let prob = sum * 100.0;
        if prob < MIN_RECOVERY_PROBABILITY {
            return Err(UploadError::InvalidOptions(format!(
                "not enough redundancy {data_shards}-of-{total_shards}: recovery probability {:.2}% is below minimum threshold of {MIN_RECOVERY_PROBABILITY:.2}%",
                (prob * 100.0).floor() / 100.0
            )));
        }
        Ok(())
    }
}

impl Default for UploadOptions {
    fn default() -> Self {
        Self {
            data_shards: 10,
            parity_shards: 20,
            max_inflight: 90,
            shard_uploaded: None,
        }
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
    use crate::download::Download;
    use crate::hosts::QueueError;
    use crate::rhp4::Client;
    use crate::upload::{PackedUpload, upload_object};
    use bytes::{Bytes, BytesMut};
    use sia_core::rhp4::SECTOR_SIZE;
    use sia_core::signing::PrivateKey;
    use sia_core::types::v2::NetAddress;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::Mutex;
    use tokio::io::copy;

    use crate::time::Duration;

    use super::*;

    const OPTIMAL_DATA_SIZE: u64 = SECTOR_SIZE as u64 * 10; // 10 sectors per slab

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
            let hosts = Hosts::new(Client::new());
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
            let input: Bytes = Bytes::from("Hello, world!");

            let mut packed_upload = PackedUpload::new(hosts.clone(), app_key.clone(), UploadOptions::default()).unwrap();
            assert_eq!(packed_upload.remaining(), OPTIMAL_DATA_SIZE);

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
                OPTIMAL_DATA_SIZE - (input.len() * 2) as u64
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
            let mut download = Download::new(
                &objects[0],
                hosts.clone(),
                app_key.clone(),
                DownloadOptions::default(),
            )
            .unwrap();
            copy(&mut download, &mut Cursor::new(&mut output[..]))
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), input.clone());

            let mut output = BytesMut::zeroed(13);
            let mut download = Download::new(
                &objects[1],
                hosts.clone(),
                app_key.clone(),
                DownloadOptions::default(),
            )
            .unwrap();
            copy(&mut download, &mut Cursor::new(&mut output[..]))
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), input.clone());
        }).await }

        async fn test_upload_download_packed_spanning() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(Client::new());
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
            let small_input = Bytes::from("Hello, world!");

            let mut large_input = BytesMut::zeroed(OPTIMAL_DATA_SIZE as usize + 18); // 1 full slab + 18 bytes
            random_bytes(&mut large_input);
            let large_input = large_input.freeze();

            let mut packed_upload = PackedUpload::new(hosts.clone(), app_key.clone(), UploadOptions::default()).unwrap();
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
            // its length must be OPTIMAL_DATA_SIZE - 13. The second slab has the remaining bytes.
            assert_eq!(objects[1].size(), OPTIMAL_DATA_SIZE + 18);
            assert_eq!(objects[1].slabs()[0].offset, 13);
            assert_eq!(objects[1].slabs()[0].length, (OPTIMAL_DATA_SIZE - 13) as u32);
            assert_eq!(objects[1].slabs()[1].offset, 0);
            assert_eq!(objects[1].slabs()[1].length, 18 + 13);

            let mut output = BytesMut::zeroed(objects[0].size() as usize);
            let mut download = Download::new(
                &objects[0],
                hosts.clone(),
                app_key.clone(),
                DownloadOptions::default(),
            )
            .unwrap();
            copy(&mut download, &mut Cursor::new(&mut output[..]))
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), small_input);

            let mut output = BytesMut::zeroed(objects[1].size() as usize);
            let mut download = Download::new(
                &objects[1],
                hosts.clone(),
                app_key.clone(),
                DownloadOptions::default(),
            )
            .unwrap();
            copy(&mut download, &mut Cursor::new(&mut output[..]))
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), large_input);
        }).await }

    async fn test_upload_download_packed_exact() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(Client::new());
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
            let mut exact_input = BytesMut::zeroed(OPTIMAL_DATA_SIZE as usize); // 1 full slab
            random_bytes(&mut exact_input);
            let exact_input = exact_input.freeze();

            let mut packed_upload = PackedUpload::new(hosts.clone(), app_key.clone(), UploadOptions::default()).unwrap();
            packed_upload
                .add(Cursor::new(exact_input.clone()))
                .await
                .expect("add 1 to complete");

            let objects = packed_upload.finalize().await.expect("upload to finish");
            assert_eq!(objects.len(), 1);

            // The first object should have 1 slab, since it fits exactly
            assert_eq!(objects[0].slabs().len(), 1);
            // the first slab of obj[0] should be the full length. the second slab should be the remaining 18 bytes.
            assert_eq!(objects[0].size(), OPTIMAL_DATA_SIZE);
            assert_eq!(objects[0].slabs()[0].offset, 0);
            assert_eq!(objects[0].slabs()[0].length, OPTIMAL_DATA_SIZE as u32);

            let mut output = BytesMut::zeroed(objects[0].size() as usize);
            let mut download = Download::new(
                &objects[0],
                hosts.clone(),
                app_key.clone(),
                DownloadOptions::default(),
            )
            .unwrap();
            copy(&mut download, &mut Cursor::new(&mut output[..]))
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), exact_input);
        }).await }

    async fn test_upload_download_packed_empty() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(Client::new());
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
            let non_empty: Bytes = Bytes::from("hello");

            let mut packed_upload =
                PackedUpload::new(hosts.clone(), app_key.clone(), UploadOptions::default())
                    .unwrap();
            // empty at head, between, and tail; interleaved with a non-empty.
            packed_upload
                .add(Cursor::new(Bytes::new()))
                .await
                .expect("add empty 1 to complete");
            packed_upload
                .add(Cursor::new(non_empty.clone()))
                .await
                .expect("add non-empty to complete");
            packed_upload
                .add(Cursor::new(Bytes::new()))
                .await
                .expect("add empty 2 to complete");

            let objects = packed_upload.finalize().await.expect("upload to finish");
            assert_eq!(objects.len(), 3);

            // empty objects have zero slabs and zero size
            assert_eq!(objects[0].slabs().len(), 0);
            assert_eq!(objects[0].size(), 0);
            assert_eq!(objects[2].slabs().len(), 0);
            assert_eq!(objects[2].size(), 0);

            // the non-empty object should round-trip normally
            assert_eq!(objects[1].slabs().len(), 1);
            assert_eq!(objects[1].size(), non_empty.len() as u64);
            let mut output = BytesMut::zeroed(non_empty.len());
            let mut download = Download::new(
                &objects[1],
                hosts.clone(),
                app_key.clone(),
                DownloadOptions::default(),
            )
            .unwrap();
            copy(&mut download, &mut Cursor::new(&mut output[..]))
                .await
                .expect("download to complete");
            assert_eq!(output.freeze(), non_empty);
        }).await }

    async fn test_upload_packed_add_error_is_recoverable() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(Client::new());
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

            // reader that delivers `data` then errors on the next poll.
            struct ErrAfter {
                data: Vec<u8>,
                pos: usize,
            }
            impl tokio::io::AsyncRead for ErrAfter {
                fn poll_read(
                    mut self: std::pin::Pin<&mut Self>,
                    _cx: &mut std::task::Context<'_>,
                    buf: &mut tokio::io::ReadBuf<'_>,
                ) -> std::task::Poll<std::io::Result<()>> {
                    if self.pos >= self.data.len() {
                        return std::task::Poll::Ready(Err(std::io::Error::other("boom")));
                    }
                    let n = (self.data.len() - self.pos).min(buf.remaining());
                    buf.put_slice(&self.data[self.pos..self.pos + n]);
                    self.pos += n;
                    std::task::Poll::Ready(Ok(()))
                }
            }

            let partial: Vec<u8> = (0..100u8).collect();
            let good: Bytes = Bytes::from_static(b"recoverable object data after the hole");

            let mut packed_upload = PackedUpload::new(
                hosts.clone(),
                app_key.clone(),
                UploadOptions::default(),
            )
            .unwrap();
            packed_upload
                .add(ErrAfter { data: partial.clone(), pos: 0 })
                .await
                .expect_err("erroring reader should fail the add");

            // errored add left `partial.len()` bytes as dead padding in the slab;
            // the packer stays usable and subsequent adds stay aligned.
            assert_eq!(packed_upload.length(), partial.len() as u64);

            packed_upload
                .add(Cursor::new(good.clone()))
                .await
                .expect("subsequent add after errored add must succeed");

            let objects = packed_upload.finalize().await.expect("finalize");
            // only the successful add registered an object
            assert_eq!(objects.len(), 1);
            assert_eq!(objects[0].size(), good.len() as u64);
            // the good object's bytes start *after* the padding from the errored add
            assert_eq!(objects[0].slabs().len(), 1);
            assert_eq!(objects[0].slabs()[0].offset, partial.len() as u32);
            assert_eq!(objects[0].slabs()[0].length, good.len() as u32);

            let mut output = BytesMut::zeroed(good.len());
            let mut download = Download::new(
                &objects[0],
                hosts.clone(),
                app_key.clone(),
                DownloadOptions::default(),
            )
            .unwrap();
            copy(&mut download, &mut Cursor::new(&mut output[..]))
                .await
                .expect("download to complete");
            assert_eq!(output.freeze(), good);
        }).await }

    async fn test_upload_download() { run_local(async {
        let app_key = Arc::new(AppKey::import(random_seed()));
        let hosts = Hosts::new(Client::new());
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
        let input: Bytes = Bytes::from("Hello, world!");

        let object = upload_object(hosts.clone(), app_key.clone(), Object::default(), Cursor::new(input.clone()), UploadOptions::default())
            .await
            .expect("upload to complete");

        assert_eq!(object.slabs().len(), 1);
        assert_eq!(object.size(), 13);

        let mut output = BytesMut::zeroed(object.size() as usize);
        let mut download = Download::new(&object, hosts.clone(), app_key.clone(), DownloadOptions::default()).unwrap();

        copy(&mut download, &mut Cursor::new(&mut output[..]))
            .await
            .expect("download to complete");

        assert_eq!(output.freeze(), input.clone());

        let range = 7..13;
        let mut output = BytesMut::zeroed(range.end - range.start);
        let mut download = Download::new(&object, hosts.clone(), app_key.clone(), DownloadOptions {
            offset: range.start as u64,
            length: Some((range.end - range.start) as u64),
            ..Default::default()
        }).unwrap();
        copy(&mut download, &mut Cursor::new(&mut output[..]))
            .await
            .expect("download to complete");

        assert_eq!(output.freeze(), input.slice(range));
    }).await }

        async fn test_upload_append() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(Client::new());
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
            let part1 = Bytes::from("Hello, ");
            let part2 = Bytes::from("world!");
            let expected = Bytes::from("Hello, world!");

            // first upload
            let object = upload_object(hosts.clone(), app_key.clone(), Object::default(), Cursor::new(part1.clone()), UploadOptions::default())
                .await
                .expect("first upload to complete");
            assert_eq!(object.size(), part1.len() as u64);

            // resume with second part
            let object = upload_object(hosts.clone(), app_key.clone(), object, Cursor::new(part2.clone()), UploadOptions::default())
                .await
                .expect("second upload to complete");
            assert_eq!(object.size(), expected.len() as u64);

            // download the full object and verify concatenation
            let mut output = BytesMut::zeroed(expected.len());
            let mut download = Download::new(
                &object,
                hosts.clone(),
                app_key.clone(),
                DownloadOptions::default(),
            )
            .unwrap();
            copy(&mut download, &mut Cursor::new(&mut output[..]))
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), expected);
        }).await }

        /// Port of Go SDK's client_test.go:TestDownload "ranges" subtest
    async fn test_download_ranges() { run_local(async {
            use sia_core::rhp4::SECTOR_SIZE;
            const SEGMENT_SIZE: u64 = 64; // leaf size

            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(Client::new());
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
            // Use default 10 data shards, so optimal_data_size = 10 * SECTOR_SIZE
            let optimal_data_size = 10 * SECTOR_SIZE as u64;
            let data_size = optimal_data_size * 3; // 3 slabs

            let mut data = BytesMut::zeroed(data_size as usize);
            random_bytes(&mut data);
            let data = data.freeze();

            let object = upload_object(hosts.clone(), app_key.clone(), Object::default(), Cursor::new(data.clone()), UploadOptions::default())
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
                (optimal_data_size / 2, 2 * optimal_data_size),       // across slabs
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
                let mut download = Download::new(
                    &object,
                    hosts.clone(),
                    app_key.clone(),
                    DownloadOptions {
                        offset,
                        length: Some(length),
                        ..Default::default()
                    },
                )
                .unwrap();
                copy(&mut download, &mut output).await.unwrap();

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
            let mock_transport = Client::new();
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
            let input: Bytes = Bytes::from("Hello, world!");

            let object = upload_object(hosts.clone(), app_key.clone(), Object::default(), Cursor::new(input.clone()), UploadOptions::default())
                .await
                .expect("upload to complete");

            // make all hosts slow
            mock_transport.set_slow_hosts(
                host_keys.iter().take(30).copied(),
                Duration::from_secs(1),
            );

            let mut output = BytesMut::zeroed(object.size() as usize);
            let mut download = Download::new(
                &object,
                hosts.clone(),
                app_key.clone(),
                DownloadOptions::default(),
            )
            .unwrap();
            copy(&mut download, &mut Cursor::new(&mut output[..]))
                .await
                .expect("download to complete");

            assert_eq!(output.freeze(), input.clone());
        }).await }

    async fn test_upload_no_hosts() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(Client::new());
            let input: Bytes = Bytes::from("Hello, world!");

            let err = upload_object(hosts.clone(), app_key.clone(), Object::default(), Cursor::new(input.clone()), UploadOptions::default())
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
            let mock_transport = Client::new();
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
            let input: Bytes = Bytes::from("Hello, world!");

            let object = upload_object(hosts.clone(), app_key.clone(), Object::default(), Cursor::new(input.clone()), UploadOptions::default())
                .await
                .expect("upload should succeed with 1 slow host");

            assert_eq!(object.slabs().len(), 1);
        }).await }

        // Upload should succeed even if all initial hosts are slow
    async fn test_upload_all_hosts_slow() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let mock_transport = Client::new();
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
            let input: Bytes = Bytes::from("Hello, world!");

            let _ = upload_object(hosts.clone(), app_key.clone(), Object::default(), Cursor::new(input.clone()), UploadOptions::default())
                .await
                .expect("upload to succeed");
        }).await }

    async fn test_upload_not_enough_hosts_good_for_upload() { run_local(async {
            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(Client::new());
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
            let input: Bytes = Bytes::from("Hello, world!");

            let err = upload_object(hosts.clone(), app_key.clone(), Object::default(), Cursor::new(input.clone()), UploadOptions::default())
                .await
                .expect_err("upload to fail");

            match err {
                UploadError::QueueError(QueueError::InsufficientHosts) => (),
                _ => panic!(),
            }
        }).await }

        async fn test_progress_callbacks() { run_local(async {
            let min_shards: usize = 10;
            let total_shards: usize = 30;
            let num_slabs = 3;

            let app_key = Arc::new(AppKey::import(random_seed()));
            let hosts = Hosts::new(Client::new());
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
            let data_size = OPTIMAL_DATA_SIZE as usize * num_slabs;
            let mut data = BytesMut::zeroed(data_size);
            random_bytes(&mut data);
            let data = data.freeze();

            let upload_progress: Arc<Mutex<HashMap<(usize, usize), ShardProgress>>> = Arc::new(Mutex::new(HashMap::new()));
            let upload_progress_clone = upload_progress.clone();
            let upload_opts = UploadOptions::default()
                .on_shard_uploaded(move |p: ShardProgress| {
                    if upload_progress_clone.lock().unwrap().contains_key(&(p.slab_index, p.shard_index)) {
                        panic!("duplicate upload callback for slab {}, shard {}", p.slab_index, p.shard_index);
                    }
                    assert_eq!(p.shard_size, SECTOR_SIZE);
                    upload_progress_clone.lock().unwrap().insert((p.slab_index, p.shard_index), p);
                });
            let obj = upload_object(hosts.clone(), app_key.clone(), Object::default(), Cursor::new(data.clone()), upload_opts)
                .await
                .unwrap();
            assert_eq!(obj.slabs().len(), num_slabs);

            let upload_progress = upload_progress.lock().unwrap();
            // verify upload callbacks: exactly one per (slab_index, shard_index)
            assert_eq!(upload_progress.len(), total_shards * num_slabs,
                "upload: expected {} callbacks, got {}",
                total_shards * num_slabs, upload_progress.len());
            for i in 0..num_slabs {
                for j in 0..total_shards {
                    assert!(upload_progress.contains_key(&(i, j)),
                        "missing upload callback for slab {}, shard {}", i, j);
                }
            }

            let download_progress: Arc<Mutex<HashMap<(usize, usize), usize>>> =
                Arc::new(Mutex::new(HashMap::new()));
            let download_progress_clone = download_progress.clone();
            let download_opts = DownloadOptions::default()
                .on_shard_downloaded(move |p: ShardProgress| {
                    *download_progress_clone.lock().unwrap().entry((p.slab_index, p.shard_index)).or_default() += 1;
                });

            let mut recovered_data = Vec::with_capacity(data_size);
            let mut download = Download::new(&obj, hosts.clone(), app_key.clone(), download_opts).unwrap();
            copy(&mut download, &mut recovered_data).await.unwrap();
            assert_eq!(data, recovered_data);

            let download_progress = download_progress.lock().unwrap();
            let chunks_per_slab = OPTIMAL_DATA_SIZE as usize / (1 << 18);
            let expected_total = chunks_per_slab * min_shards * num_slabs;
            let actual_total: usize = download_progress.values().sum();
            assert_eq!(actual_total, expected_total,
                "download: expected {} total callbacks, got {}",
                expected_total, actual_total);

            for ((slab_idx, shard_idx), _) in download_progress.iter() {
                assert!(*shard_idx < total_shards, "invalid shard index {} in callback", shard_idx);
                assert!(*slab_idx < num_slabs, "invalid slab index {} in callback", slab_idx);
            }
        }).await }
        }
}
