use crate::app_client::{HostQuery, SlabPinParams};
use crate::quic::{
    DownloadError, DownloadOptions, Downloader, UploadError, UploadOptions, Uploader,
};

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use sia::signing::PrivateKey;
pub use slabs::*;

mod hosts;
pub use hosts::*;

use crate::app_client::{Account, Client, ObjectsCursor};
use sia::rhp::Host;
use sia::types::Hash256;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

pub use reqwest::{IntoUrl, Url};

mod object_encryption;
mod slabs;

pub mod app_client;
pub mod quic;

mod builder;
pub use builder::*;

#[derive(Error, Debug)]
pub enum AppKeyError {
    #[error("decode error: {0}")]
    DecodeError(#[from] base64::DecodeSliceError),
    #[error("invalid length")]
    InvalidLength,
}

mod sealed {
    pub trait Sealed {}
}

/// An AppKey is used to sign requests to the indexer.
/// It should be stored in a secure manner by the application instead
/// of storing the mnemonic directly.
pub trait AppKey: sealed::Sealed {
    type Error;

    /// Exports the AppKey to its string representation.
    /// This can be stored and later imported using [AppKey::import].
    fn export(&self) -> String;

    /// Imports an AppKey from its string representation.
    fn import(s: &str) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

impl sealed::Sealed for PrivateKey {}

impl AppKey for PrivateKey {
    type Error = AppKeyError;

    /// Exports the AppKey to its string representation.
    fn export(&self) -> String {
        let key = self.as_ref();
        BASE64_URL_SAFE_NO_PAD.encode(&key[..32])
    }

    /// Imports an AppKey from its string representation.
    fn import(s: &str) -> Result<Self, Self::Error> {
        let mut seed = [0u8; 32];
        let decoded = BASE64_URL_SAFE_NO_PAD.decode_slice(s.as_bytes(), &mut seed)?;
        if decoded != 32 {
            return Err(AppKeyError::InvalidLength);
        }
        Ok(PrivateKey::from_seed(&seed))
    }
}

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

/// The SDK provides methods for uploading and downloading objects,
/// as well as interacting with an indexer service.
#[derive(Clone)]
pub struct SDK {
    client: Client,
    app_key: PrivateKey,
    downloader: Downloader,
    uploader: Uploader,
}

impl SDK {
    /// Creates a new SDK instance.
    async fn new(
        client: Client,
        app_key: PrivateKey,
        tls_config: rustls::ClientConfig,
    ) -> Result<Self, BuilderError> {
        let hosts = client.hosts(&app_key, HostQuery::default()).await?;
        let dialer = quic::Client::new(tls_config)?;
        dialer.update_hosts(hosts);

        let downloader = Downloader::new(client.clone(), dialer.clone(), app_key.clone());
        let uploader = Uploader::new(client.clone(), dialer.clone(), app_key.clone());
        Ok(Self {
            client,
            app_key,
            downloader,
            uploader,
        })
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
