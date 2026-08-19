#[cfg(feature = "fs")]
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use log::{debug, warn};
use reqwest::IntoUrl;
use sia_core::signing::PrivateKey;
use sia_core::types::Hash256;
use thiserror::Error;
use tokio::io::AsyncRead;
use url::Url;

use crate::app_client::PinObjectError::UnpinnedSlab;
use crate::app_client::{self, SLAB_PIN_BATCH_SIZE, SlabPinParams};
use crate::hosts::Hosts;
use crate::rhp4::{Client, HostEndpoint};
use crate::sharing::{self, KeyRequest, Nonce, SharingKey};
use crate::task::AbortOnDropHandle;
use crate::time::Duration;
use crate::upload::{PackedUpload, upload_object};
use crate::{
    Account, AppKey, BuilderError, Download, DownloadError, DownloadOptions, Host, HostQuery,
    KeyResponse, Object, ObjectEvent, ObjectsCursor, PackedUploadOptions, PinnedSlab,
    SealedObjectError, SharingKeyOptions, UploadError, UploadOptions,
};

/// `SharingKey`'s operations live here so they can reach this module's private
/// fields. The type itself is defined in [`crate::sharing`].
mod sharing_key;

/// Errors that can occur when using the SDK.
#[derive(Error, Debug)]
pub enum Error {
    /// An error from the indexer API.
    #[error("app error: {0}")]
    App(String),

    /// The object is not attached to the sharing key.
    #[error("object is not attached to the sharing key")]
    ObjectNotAttached,

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
pub struct Sdk {
    app_key: Arc<AppKey>,
    api_client: app_client::Client,
    hosts: Hosts,
    _refresh_task: Arc<AbortOnDropHandle<()>>,
}

impl Sdk {
    async fn refresh_hosts(
        app_key: &AppKey,
        api_client: &app_client::Client,
        hosts: &Hosts,
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
    pub(crate) async fn new(
        api_client: app_client::Client,
        app_key: Arc<AppKey>,
    ) -> Result<Self, BuilderError> {
        Self::with_backends(api_client, Client::new(), app_key).await
    }

    /// Creates a new SDK instance with the provided backends
    pub(crate) async fn with_backends(
        api_client: app_client::Client,
        transport: Client,
        app_key: Arc<AppKey>,
    ) -> Result<Self, BuilderError> {
        let hosts = Hosts::new(transport);
        Self::refresh_hosts(&app_key, &api_client, &hosts).await?;
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
            _refresh_task: Arc::new(refresh_task),
        })
    }

    /// Spawns a background task that refreshes the host list at the given interval.
    fn spawn_refresh_task(
        app_key: Arc<AppKey>,
        api_client: app_client::Client,
        hosts: Hosts,
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
    /// The object containing the metadata needed to download. The slabs are
    /// pinned as they are uploaded, but the caller must pin the object to the
    /// indexer after uploading.
    pub async fn upload<R: AsyncRead + Unpin + 'static>(
        &self,
        object: Object,
        reader: R,
        options: UploadOptions,
    ) -> Result<Object, UploadError> {
        upload_object(
            self.hosts.clone(),
            self.api_client.clone(),
            self.app_key.clone(),
            object,
            reader,
            options,
        )
        .await
    }

    /// Uploads the file at `path`. Behaves like [upload](Self::upload)
    /// otherwise.
    ///
    /// # Arguments
    /// * `object` - The object to upload into. Use `Object::default()` for new uploads.
    /// * `path` - The path of the file to upload. It will be read until EOF.
    /// * `options` - The [UploadOptions] to use for the upload.
    ///
    /// # Returns
    /// The object containing the metadata needed to download. The caller must
    /// pin the object to the indexer after uploading.
    #[cfg(feature = "fs")]
    pub async fn upload_path<P: AsRef<Path>>(
        &self,
        object: Object,
        path: P,
        options: UploadOptions,
    ) -> Result<Object, UploadError> {
        let file = tokio::fs::File::open(path).await?;
        self.upload(object, file, options).await
    }

    /// Creates a new packed upload. This allows multiple objects to be packed together
    /// for more efficient uploads. The returned `PackedUpload` can be used to add objects to the upload, and then finalized to get the resulting objects.
    ///
    /// # Arguments
    /// * `options` - The [PackedUploadOptions] to use for the upload.
    ///
    /// # Returns
    /// A [PackedUpload] that can be used to add objects and finalize the upload.
    pub fn upload_packed(&self, options: PackedUploadOptions) -> Result<PackedUpload, UploadError> {
        PackedUpload::new(
            self.hosts.clone(),
            self.api_client.clone(),
            self.app_key.clone(),
            options,
        )
    }

    /// Returns a [Download] handle that streams the object's data. The handle
    /// implements [tokio::io::AsyncRead] — pipe it into any writer with
    /// [tokio::io::copy] or read chunks directly. In-flight chunk recovery is
    /// cancelled when the handle is dropped.
    pub fn download(
        &self,
        object: &Object,
        options: DownloadOptions,
    ) -> Result<Download, DownloadError> {
        Download::new(object, self.hosts.clone(), self.app_key.clone(), options)
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

    /// Pins an object to the indexer, pinning any of its slabs that are not
    /// already pinned.
    pub async fn pin_object(&self, object: &Object) -> Result<(), Error> {
        let sealed = object.seal(self.app_key.as_ref());
        match self.api_client.pin_object(&self.app_key.0, &sealed).await {
            Ok(()) => return Ok(()),
            Err(UnpinnedSlab) => {}
            Err(e) => return Err(Error::App(format!("{e:?}"))),
        }

        for slabs in object.slabs().chunks(SLAB_PIN_BATCH_SIZE) {
            let params: Vec<SlabPinParams> = slabs.iter().map(SlabPinParams::from).collect();
            let ids = self
                .api_client
                .pin_slabs(&self.app_key.0, &params)
                .await
                .map_err(|e| Error::App(format!("{e:?}")))?;
            if ids.len() != slabs.len()
                || ids.iter().zip(slabs).any(|(id, slab)| id != &slab.digest())
            {
                return Err(Error::App("slab id mismatch".to_string()));
            }
        }

        self.api_client
            .pin_object(&self.app_key.0, &sealed)
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

    /// Creates a sharing key. Attach objects to it with
    /// [`SharingKey::add_object`].
    ///
    /// # Arguments
    /// * `options` - The [SharingKeyOptions] to create the key with.
    pub async fn create_sharing_key(
        &self,
        options: SharingKeyOptions,
    ) -> Result<SharingKey, Error> {
        let nonce = Nonce(rand::random());
        let sharing_key =
            PrivateKey::from_seed(&sharing::derive_sharing_seed(&self.app_key.0, &nonce));
        let req = KeyRequest::new(&sharing_key, nonce, options.description, options.expires_at);
        let created = self
            .api_client
            .add_sharing_key(&self.app_key.0, &req)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        // Checked against the locally generated nonce so an indexer echoing a
        // different key of this account cannot make the caller seal objects
        // under it.
        if created.key.nonce != nonce || created.key.public_key != sharing_key.public_key() {
            return Err(Error::App(
                "indexer returned a different sharing key than was created".into(),
            ));
        }
        Ok(created.key)
    }

    /// Lists the account's sharing keys.
    pub async fn sharing_keys(&self, offset: u64, limit: u64) -> Result<Vec<KeyResponse>, Error> {
        self.api_client
            .sharing_keys(&self.app_key.0, offset, limit)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Fetches the indexer's current record for `key`.
    pub async fn sharing_key(&self, key: &SharingKey) -> Result<KeyResponse, Error> {
        let record = self
            .api_client
            .sharing_key(&self.app_key.0, &key.public_key)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        if record.key != *key {
            return Err(Error::App(
                "indexer returned a different sharing key than requested".into(),
            ));
        }
        Ok(record)
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod test {
    use super::*;
    use crate::KeyStats;
    use sia_core::signing::PrivateKey;

    fn random_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        seed
    }

    /// The whole sharing flow against the in-memory network: an owner creates a
    /// key and attaches an object, and a recipient holding only the seed lists,
    /// decrypts, and downloads it.
    #[tokio::test]
    async fn test_mock_network_sharing_roundtrip() {
        use std::io::Cursor;
        use tokio::io::AsyncReadExt;

        use crate::mock::MockNetwork;

        let network = MockNetwork::new();
        network.add_hosts(40);
        let sdk = network
            .sdk(AppKey::import(random_seed()))
            .await
            .expect("sdk creation failed");

        let data: Vec<u8> = (0..(1 << 20)).map(|i| i as u8).collect();
        let object = sdk
            .upload(
                Object::new(Some(b"metadata".to_vec())),
                Cursor::new(data.clone()),
                UploadOptions::default(),
            )
            .await
            .expect("upload failed");
        sdk.pin_object(&object).await.expect("pin failed");

        let key = sdk
            .create_sharing_key(SharingKeyOptions {
                description: "photos".to_string(),
                ..Default::default()
            })
            .await
            .expect("create failed");
        key.add_object(&sdk, &object).await.expect("attach failed");

        // the owner's view of what is attached
        let attached = key.objects(&sdk, 0, 10).await.expect("owner list failed");
        assert_eq!(attached.len(), 1);
        assert_eq!(attached[0].id(), object.id());

        let record = sdk.sharing_key(&key).await.expect("re-read failed");
        assert_eq!(record.stats.object_count, 1);
        assert_eq!(record.description, "photos");

        // the recipient holds nothing but the seed
        let seed = key.seed(&sdk).expect("seed failed");
        let shared = network.shared_sdk(seed).await.expect("connect failed");

        let stats = shared.stats().await.expect("stats failed");
        assert_eq!(stats.object_count, 1);

        let listed = shared.objects(0, 10).await.expect("list failed");
        assert_eq!(listed.len(), 1);

        // re-sealing under the sharing key must round-trip, or a recipient can
        // decrypt nothing at all
        let fetched = shared.object(&object.id()).await.expect("fetch failed");
        assert_eq!(fetched.slabs(), object.slabs());
        assert_eq!(fetched.metadata, b"metadata".to_vec());

        let mut reader = shared
            .download(&fetched, DownloadOptions::default())
            .expect("download failed");
        let mut downloaded = Vec::new();
        reader
            .read_to_end(&mut downloaded)
            .await
            .expect("read failed");
        assert_eq!(downloaded, data);

        // detaching leaves the key in place with nothing attached
        key.delete_object(&sdk, &object.id())
            .await
            .expect("detach failed");
        assert_eq!(shared.stats().await.expect("stats failed").object_count, 0);
    }

    #[tokio::test]
    async fn test_mock_network_object_roundtrip() {
        use std::io::Cursor;
        use tokio::io::AsyncReadExt;

        use crate::mock::MockNetwork;

        let network = MockNetwork::new();
        network.add_hosts(40);

        let sdk = network
            .sdk(AppKey::import(random_seed()))
            .await
            .expect("sdk creation failed");

        let data: Vec<u8> = (0..(1 << 20)).map(|i| i as u8).collect();
        let object = sdk
            .upload(
                Object::new(Some(b"metadata".to_vec())),
                Cursor::new(data.clone()),
                UploadOptions::default(),
            )
            .await
            .expect("upload failed");
        assert!(!object.slabs().is_empty());
        // The slabs are pinned as they are uploaded, before the object is pinned.
        assert_eq!(network.pinned_slabs(), object.slabs().len());

        // Simulate an imported object whose slabs have not been pinned by this
        // account. pin_object should pin them and retry.
        sdk.prune_slabs().await.expect("prune failed");
        assert_eq!(network.pinned_slabs(), 0);
        sdk.pin_object(&object).await.expect("pin failed");
        assert_eq!(network.pinned_slabs(), object.slabs().len());

        // the indexer stores the sealed object, so this round-trips through
        // seal/open rather than handing back what was pinned
        let fetched = sdk.object(&object.id()).await.expect("object fetch failed");
        assert_eq!(fetched.slabs(), object.slabs());
        assert_eq!(fetched.metadata, b"metadata".to_vec());

        let mut reader = sdk
            .download(&fetched, DownloadOptions::default())
            .expect("download failed");
        let mut downloaded = Vec::new();
        reader
            .read_to_end(&mut downloaded)
            .await
            .expect("read failed");
        assert_eq!(downloaded, data);

        sdk.delete_object(&object.id())
            .await
            .expect("delete failed");
        assert!(sdk.object(&object.id()).await.is_err());

        sdk.prune_slabs().await.expect("prune failed");
        assert_eq!(network.pinned_slabs(), 0);
    }

    #[tokio::test]
    async fn test_refresh_task_periodic_and_abort() {
        use std::sync::Arc;

        use crate::time::Duration;
        use httptest::http::{Response, StatusCode};
        use httptest::matchers::*;
        use httptest::{Expectation, Server};
        use sia_core::signing::PrivateKey;
        use sia_core::types::v2::NetAddress;

        use crate::hosts::Hosts;
        use crate::{AppKey, Host};

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
        let hosts = Hosts::new(crate::rhp4::Client::mock());

        // helper: seed one good-for-upload host so available_for_upload() == 1
        let add_upload_host = |hosts: &Hosts| {
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
        Sdk::refresh_hosts(&app_key, &client, &hosts).await.unwrap();
        assert_eq!(
            hosts.available_for_upload(),
            0,
            "initial refresh should clear upload hosts"
        );

        // spawn the periodic refresh task with a short interval
        add_upload_host(&hosts);
        assert_eq!(hosts.available_for_upload(), 1);
        let handle =
            Sdk::spawn_refresh_task(app_key.clone(), client.clone(), hosts.clone(), INTERVAL);

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

    // An indexer that echoes a different sharing key than the one created must
    // be rejected before anything is sealed under it, and without deleting the
    // key it named, which may be a real key of the account.
    #[tokio::test]
    async fn test_create_sharing_key_rejects_substituted_key() {
        use httptest::http::{Response, StatusCode};
        use httptest::matchers::*;
        use httptest::{Expectation, Server};

        use crate::sharing::derive_sharing_seed;
        use crate::{AppKey, Host};

        let app_key = Arc::new(AppKey::import(random_seed()));

        // A *genuine* other key of this account: its nonce and public key agree,
        // so only comparing against the locally generated nonce catches it.
        let other_nonce = Nonce([9u8; 32]);
        let other_seed = derive_sharing_seed(&app_key.0, &other_nonce);
        let substituted = KeyResponse {
            key: SharingKey {
                public_key: PrivateKey::from_seed(&other_seed).public_key(),
                nonce: other_nonce,
            },
            account: app_key.public_key(),
            description: "photos".to_string(),
            stats: KeyStats {
                object_count: 0,
                object_size: 0,
                pinned_data: 0,
                pinned_size: 0,
                expires_at: None,
                created_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                updated_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            },
        };

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/hosts"))
                .times(..)
                .respond_with(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(serde_json::to_string(&Vec::<Host>::new()).unwrap())
                        .unwrap(),
                ),
        );
        server.expect(
            Expectation::matching(request::method_path("POST", "/sharing")).respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(serde_json::to_string(&substituted).unwrap())
                    .unwrap(),
            ),
        );
        // No attach and no delete must be issued. httptest panics on any request
        // it has no expectation for, so the absence of stubs is the assertion.
        let client = crate::app_client::Client::new(server.url("/").to_string()).unwrap();
        let sdk = Sdk::new(client, app_key)
            .await
            .expect("failed to build sdk");

        let err = sdk
            .create_sharing_key(SharingKeyOptions {
                description: "photos".to_string(),
                ..Default::default()
            })
            .await
            .expect_err("a substituted key must be rejected");
        assert!(format!("{err}").contains("different sharing key"), "{err}");
    }

    // Fetching a key by its public key must reject a record for a *different*
    // key. The substitute here is a genuine key of the same account, so its
    // nonce and public key agree and `SharingKey`'s own derivation check passes;
    // only comparing against the requested key catches it.
    #[tokio::test]
    async fn test_sharing_key_rejects_another_key_of_the_account() {
        use httptest::http::{Response, StatusCode};
        use httptest::matchers::*;
        use httptest::{Expectation, Server};

        use crate::sharing::derive_sharing_seed;
        use crate::{AppKey, Host};

        let app_key = Arc::new(AppKey::import(random_seed()));
        let account_key =
            |nonce| PrivateKey::from_seed(&derive_sharing_seed(&app_key.0, &nonce)).public_key();

        let requested_nonce = Nonce([1u8; 32]);
        let requested = SharingKey {
            public_key: account_key(requested_nonce),
            nonce: requested_nonce,
        };
        let other_nonce = Nonce([9u8; 32]);
        let substituted = KeyResponse {
            key: SharingKey {
                public_key: account_key(other_nonce),
                nonce: other_nonce,
            },
            account: app_key.public_key(),
            description: "photos".to_string(),
            stats: KeyStats {
                object_count: 0,
                object_size: 0,
                pinned_data: 0,
                pinned_size: 0,
                expires_at: None,
                created_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                updated_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            },
        };
        assert_ne!(substituted.key.public_key, requested.public_key);

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/hosts"))
                .times(..)
                .respond_with(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(serde_json::to_string(&Vec::<Host>::new()).unwrap())
                        .unwrap(),
                ),
        );
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!("/sharing/{}", requested.public_key),
            ))
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(serde_json::to_string(&substituted).unwrap())
                    .unwrap(),
            ),
        );

        let client = crate::app_client::Client::new(server.url("/").to_string()).unwrap();
        let sdk = Sdk::new(client, app_key)
            .await
            .expect("failed to build sdk");

        let err = sdk
            .sharing_key(&requested)
            .await
            .expect_err("a record for another key must be rejected");
        assert!(
            format!("{err}").contains("different sharing key than requested"),
            "{err}"
        );
    }
}
