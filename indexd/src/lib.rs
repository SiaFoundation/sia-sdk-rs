use std::sync::Arc;

use crate::app_client::{HostQuery, SlabPinParams};
use crate::rhp4::RHP4Client;

use chrono::{DateTime, Utc};
use sia::signing::PrivateKey;
pub use slabs::*;

mod hosts;
pub use hosts::*;

use crate::app_client::{Account, ObjectsCursor};
use sia::rhp::Host;
use sia::types::Hash256;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

pub use reqwest::{IntoUrl, Url};

mod rhp4;
mod upload;
pub use upload::*;

mod download;
pub use download::*;

mod object_encryption;
mod slabs;

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

#[derive(Clone)]
pub struct SDK {
    app_key: Arc<PrivateKey>,
    api_client: app_client::Client,
    downloader: Downloader<quic::Client>,
    uploader: Uploader<quic::Client, app_client::Client>,
}

impl SDK {
    /// Creates a new SDK instance.
    async fn new(
        api_client: app_client::Client,
        app_key: Arc<PrivateKey>,
        tls_config: rustls::ClientConfig,
    ) -> Result<Self, BuilderError> {
        let usable_hosts = api_client.hosts(&app_key, HostQuery::default()).await?;
        let hosts = Hosts::new();
        hosts.update(usable_hosts);

        let transport = quic::Client::new(tls_config, hosts.clone())?;

        let downloader = Downloader::new(hosts.clone(), transport.clone(), app_key.clone());
        let uploader = Uploader::new(
            api_client.clone(),
            hosts.clone(),
            transport.clone(),
            app_key.clone(),
        );
        Ok(Self {
            app_key,
            api_client,
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
        self.api_client
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
        self.api_client
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
    pub async fn shared_object<U: IntoUrl>(&self, share_url: U) -> Result<SharedObject, Error> {
        let share_url = share_url
            .into_url()
            .map_err(|e| Error::App(format!("{e:?}")))?;
        self.api_client
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

        self.api_client
            .pin_slabs(&self.app_key, slabs)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        let object: Object = shared_object.into();
        self.api_client
            .save_object(&self.app_key, &object.seal(&self.app_key))
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        Ok(object)
    }

    /// Retrieves a pinned slab from the indexer by its id.
    pub async fn slab(&self, id: &Hash256) -> Result<PinnedSlab, Error> {
        self.api_client
            .slab(&self.app_key, id)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }
}

#[cfg(test)]
mod test {
    use bytes::{Bytes, BytesMut};
    use sia::rhp::{self, HostPrices};
    use sia::signing::{PublicKey, Signature};
    use sia::types::Currency;
    use sia::types::v2::NetAddress;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::RwLock;

    use super::*;

    struct NoOpPinner {}

    impl Pinner for Arc<NoOpPinner> {
        async fn pin_slab(
            &self,
            _: &PrivateKey,
            params: SlabPinParams,
        ) -> Result<Hash256, app_client::Error> {
            let s = Slab {
                min_shards: params.min_shards,
                encryption_key: params.encryption_key,
                sectors: params.sectors,
                length: 0,
                offset: 0,
            };
            Ok(s.digest())
        }

        async fn save_object(
            &self,
            _: &PrivateKey,
            _: &SealedObject,
        ) -> Result<(), app_client::Error> {
            Ok(())
        }
    }

    struct TestRHP4Client {
        sectors: RwLock<HashMap<PublicKey, HashMap<Hash256, Bytes>>>,
    }

    impl TestRHP4Client {
        fn new() -> Self {
            Self {
                sectors: RwLock::new(HashMap::new()),
            }
        }
    }

    impl RHP4Client for Arc<TestRHP4Client> {
        async fn host_prices(&self, _: PublicKey, _: bool) -> Result<HostPrices, rhp4::Error> {
            Ok(HostPrices {
                contract_price: Currency::zero(),
                collateral: Currency::zero(),
                ingress_price: Currency::zero(),
                egress_price: Currency::zero(),
                storage_price: Currency::zero(),
                free_sector_price: Currency::zero(),
                tip_height: 0,
                signature: Signature::default(),
                valid_until: Utc::now() + chrono::Duration::days(1),
            })
        }

        async fn write_sector(
            &self,
            host_key: PublicKey,
            _: &PrivateKey,
            sector: Bytes,
        ) -> Result<Hash256, rhp4::Error> {
            let mut sectors = self.sectors.write().unwrap();
            let host_sectors = sectors.entry(host_key).or_default();
            let sector_root = rhp::sector_root(&sector);
            host_sectors.insert(sector_root, sector);
            Ok(sector_root)
        }

        async fn read_sector(
            &self,
            host_key: PublicKey,
            _: &PrivateKey,
            root: Hash256,
            offset: usize,
            length: usize,
        ) -> Result<Bytes, rhp4::Error> {
            let sectors = self.sectors.read().unwrap();
            let host_sectors = sectors
                .get(&host_key)
                .ok_or_else(|| rhp4::Error::Transport("host not found".to_string()))?;
            let sector = host_sectors
                .get(&root)
                .cloned()
                .ok_or_else(|| rhp4::Error::Transport("sector not found".to_string()))?;
            Ok(sector.slice(offset..offset + length))
        }
    }

    #[tokio::test]
    async fn test_upload_download() {
        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let noop_pinner = Arc::new(NoOpPinner {});
        let transport = Arc::new(TestRHP4Client::new());
        let hosts = Hosts::new();

        hosts.update(
            (0..60)
                .map(|_| Host {
                    public_key: PrivateKey::from_seed(&rand::random()).public_key(),
                    addresses: vec![NetAddress {
                        protocol: sia::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                })
                .collect(),
        );

        let uploader = Uploader::new(
            noop_pinner.clone(),
            hosts.clone(),
            transport.clone(),
            app_key.clone(),
        );
        let downloader = Downloader::new(hosts.clone(), transport.clone(), app_key.clone());

        let input: Bytes = Bytes::from("Hello, world!");

        let object = uploader
            .upload(
                CancellationToken::new(),
                Cursor::new(input.clone()),
                UploadOptions::default(),
            )
            .await
            .expect("upload to complete");

        assert_eq!(object.slabs().len(), 1);
        assert_eq!(object.size(), 13);

        let mut output = BytesMut::zeroed(object.size() as usize);
        downloader
            .download(
                Cursor::new(&mut output[..]),
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
                Cursor::new(&mut output[..]),
                &object,
                DownloadOptions {
                    offset: range.start,
                    length: Some(range.end - range.start),
                    ..Default::default()
                },
            )
            .await
            .expect("download to complete");

        assert_eq!(output.freeze(), input.slice(range));
    }
}
