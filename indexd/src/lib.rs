use crate::app_client::{HostQuery, SlabPinParams};
use crate::download::{DownloadError, DownloadOptions, Downloader};
use crate::upload::{UploadError, UploadOptions, Uploader};

use chrono::{DateTime, Utc};
use sia::signing::PrivateKey;
pub use slabs::*;

mod hosts;
pub use hosts::*;

use crate::app_client::{Account, Client, ObjectsCursor};
use bytes::Bytes;
use sia::rhp::Host;
use sia::signing::PublicKey;
use sia::types::Hash256;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

pub use reqwest::{IntoUrl, Url};

pub mod download;
mod object_encryption;
mod slabs;
pub mod upload;

pub mod app_client;
pub mod quic;

mod builder;
pub use builder::*;

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

pub trait HostClient: Clone + Send + Sync + 'static {
    type Error: std::error::Error;

    /// Returns a reference to the client's internal Hosts state.
    fn hosts(&self) -> &Hosts;

    /// Reads a segment of a sector from a host.
    ///
    /// # Arguments
    /// * `host_key` - The public key of the host to read from.
    /// * `account_key` - The private key of the account to pay with.
    /// * `root` - The root hash of the sector to read from.
    /// * `offset` - The offset within the sector to start reading from.
    /// * `length` - The length of the segment to read.
    ///
    /// # Returns
    /// A `Bytes` object containing the requested data segment. The
    /// returned data is validated against the sector's Merkle root.
    fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> impl Future<Output = Result<Bytes, Self::Error>> + Send;

    /// Writes a sector to a host and returns the root hash.
    fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> impl Future<Output = Result<Hash256, Self::Error>> + Send;
}

/// The SDK provides methods for uploading and downloading objects,
/// as well as interacting with an indexer service.
#[derive(Clone)]
pub struct SDK<C: HostClient> {
    client: Client,
    app_key: PrivateKey,
    downloader: Downloader<C>,
    uploader: Uploader<C>,
}

impl SDK<quic::Client> {
    /// Creates a new SDK instance using QUIC as the transport protocol.
    pub async fn new_quic(
        app_client: Client,
        app_key: PrivateKey,
        tls_config: rustls::ClientConfig,
    ) -> Result<SDK<quic::Client>, BuilderError> {
        let host_client = quic::Client::new(tls_config)?;
        SDK::new(app_client, host_client, app_key).await
    }
}

impl<C: HostClient> SDK<C>
where
    UploadError: From<C::Error>,
    DownloadError: From<C::Error>,
{
    /// Creates a new SDK instance.
    async fn new(
        app_client: Client,
        host_client: C,
        app_key: PrivateKey,
    ) -> Result<Self, BuilderError> {
        let hosts = app_client.hosts(&app_key, HostQuery::default()).await?;
        host_client.hosts().update(hosts);

        let downloader = Downloader::new(app_client.clone(), host_client.clone(), app_key.clone());
        let uploader = Uploader::new(app_client.clone(), host_client.clone(), app_key.clone());
        Ok(Self {
            client: app_client,
            app_key,
            downloader,
            uploader,
        })
    }

    /// Returns the application key used by the SDK.
    ///
    /// This should be kept secret and secure. Applications
    /// should store it safely.
    pub fn app_key(&self) -> &PrivateKey {
        &self.app_key
    }

    /// Uploads an object using the provided reader and options.
    pub async fn upload<R: AsyncReadExt + Unpin + Send + 'static>(
        &self,
        cancel: CancellationToken,
        reader: R,
        options: UploadOptions,
    ) -> Result<Object, Error> {
        let object = self.uploader.upload(cancel, reader, options).await?;
        Ok(object)
    }

    /// Downloads an object using the provided writer and options.
    pub async fn download<W: AsyncWriteExt + Unpin>(
        &self,
        w: W,
        object: &Object,
        options: DownloadOptions,
    ) -> Result<(), Error> {
        self.downloader.download(w, object, options).await?;
        Ok(())
    }

    /// Downloads a shared object using the provided writer and options.
    pub async fn download_shared<W: AsyncWriteExt + Unpin>(
        &self,
        w: W,
        object: &SharedObject,
        options: DownloadOptions,
    ) -> Result<(), Error> {
        self.downloader.download_shared(w, object, options).await?;
        Ok(())
    }

    /// Retrieves a list of hosts from the indexer matching the provided query
    /// that can be used for uploading and downloading data.
    ///
    /// # Arguments
    /// * `query` - Filtering criteria to select hosts.
    pub async fn hosts(&self, query: HostQuery) -> Result<Vec<Host>, Error> {
        self.client
            .hosts(&self.app_key, query)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Retrieves account information from the indexer.
    pub async fn account(&self) -> Result<Account, Error> {
        self.client
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
            .client
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
            .client
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
                    key: event.key,
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
        self.client
            .prune_slabs(&self.app_key)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        Ok(())
    }

    /// Saves the given object to the indexer.
    ///
    /// # Arguments
    /// * `object` - The object to save.
    pub async fn save_object(&self, object: &Object) -> Result<(), Error> {
        let sealed = object.seal(&self.app_key);
        self.client
            .save_object(&self.app_key, &sealed)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        Ok(())
    }

    /// Deletes the object with the given id.
    ///
    /// # Arguments
    /// * `id` - The id of the object to delete.
    pub async fn delete_object(&self, id: &Hash256) -> Result<(), Error> {
        self.client
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
        self.client
            .shared_object_url(&self.app_key, object, valid_until)
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Retrieves a shared object from the given share URL.
    ///
    /// # Arguments
    /// * `share_url` - The URL of the shared object.
    pub async fn shared_object<U: IntoUrl>(&self, share_url: U) -> Result<SharedObject, Error> {
        let share_url = share_url
            .into_url()
            .map_err(|e| Error::App(format!("{e:?}")))?;
        self.client
            .shared_object(share_url)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Pins a shared object to the indexer, making it available for download.
    pub async fn pin_shared(&self, shared_object: SharedObject) -> Result<Object, Error> {
        let slabs = shared_object
            .slabs()
            .iter()
            .map(|s| SlabPinParams {
                encryption_key: s.encryption_key.clone(),
                min_shards: s.min_shards,
                sectors: s.sectors.clone(),
            })
            .collect();

        self.client
            .pin_slabs(&self.app_key, slabs)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        let object: Object = shared_object.into();
        self.client
            .save_object(&self.app_key, &object.seal(&self.app_key))
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        Ok(object)
    }

    /// Retrieves a pinned slab from the indexer by its id.
    pub async fn slab(&self, id: &Hash256) -> Result<PinnedSlab, Error> {
        self.client
            .slab(&self.app_key, id)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }
}
