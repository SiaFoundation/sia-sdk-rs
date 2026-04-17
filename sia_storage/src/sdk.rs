use std::sync::Arc;

use chrono::{DateTime, Utc};
use log::{debug, warn};
use reqwest::IntoUrl;
use sia_core::types::Hash256;
use thiserror::Error;
use tokio::io::AsyncRead;
use url::Url;

use crate::app_client::{self, SlabPinParams};
use crate::hosts::Hosts;
use crate::rhp4::{Client, HostEndpoint};
use crate::task::AbortOnDropHandle;
use crate::time::Duration;
use crate::upload::Uploader;
use crate::{
    Account, AppKey, BuilderError, Download, DownloadError, DownloadOptions, Host, HostQuery,
    Object, ObjectEvent, ObjectsCursor, PackedUpload, PinnedSlab, SealedObjectError, UploadError,
    UploadOptions,
};

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
pub struct Sdk {
    app_key: Arc<AppKey>,
    api_client: app_client::Client,
    hosts: Hosts<Client>,
    uploader: Uploader<Client>,
    _refresh_task: Arc<AbortOnDropHandle<()>>,
}

impl Sdk {
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
    pub(crate) async fn new(
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
    pub async fn upload<R: AsyncRead + Unpin + 'static>(
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
}

#[cfg(test)]
mod test {
    use super::*;

    fn random_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        seed
    }

    #[cfg(not(target_arch = "wasm32"))]
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
}
