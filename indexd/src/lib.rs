use std::sync::Arc;

use crate::app_client::{HostQuery, SlabPinParams};
use crate::rhp4::RHP4Client;

use chrono::{DateTime, Utc};
use sia::signing::PrivateKey;
pub use slabs::*;

mod hosts;
pub use hosts::*;

use crate::app_client::{Account, AppClient, ObjectsCursor};
use sia::rhp::Host;
use sia::types::Hash256;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

pub use reqwest::{IntoUrl, Url};

mod rhp4;
mod upload;
pub use upload::*;

mod download;
pub use download::*;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

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
    api_client: Arc<dyn AppClient>,
    downloader: Downloader,
    uploader: Uploader<quic::Client>,
}

impl SDK {
    /// Creates a new SDK instance.
    async fn new(
        api_client: Arc<dyn AppClient>,
        app_key: Arc<PrivateKey>,
        tls_config: rustls::ClientConfig,
    ) -> Result<Self, BuilderError> {
        let usable_hosts = api_client.hosts(&app_key, HostQuery::default()).await?;
        let hosts = Hosts::new();
        hosts.update(usable_hosts);

        let transport = quic::Client::new(tls_config, hosts.clone())?;

        let downloader =
            Downloader::new(hosts.clone(), Arc::new(transport.clone()), app_key.clone());
        let uploader = Uploader::new(hosts.clone(), transport.clone(), app_key.clone());
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
            .save_object(&self.app_key, &object.seal(&self.app_key))
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

#[cfg(test)]
mod test {
    use bytes::{Bytes, BytesMut};
    use rand::Rng;
    use sia::rhp::SECTOR_SIZE;
    use sia::types::v2::NetAddress;
    use std::io::Cursor;
    use std::time::Duration;

    use crate::mock::{MockDownloader, MockRHP4Client, MockUploader};

    use super::*;

    const SLAB_SIZE: u64 = SECTOR_SIZE as u64 * 10; // 10 sectors per slab

    #[tokio::test]
    async fn test_upload_download_packed() {
        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let transport = Arc::new(MockRHP4Client::new());
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
                    good_for_upload: true,
                })
                .collect(),
        );

        let uploader = MockUploader::new(hosts.clone(), transport.clone(), app_key.clone());
        let downloader = MockDownloader::new(hosts.clone(), transport.clone(), app_key.clone());

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
        let transport = Arc::new(MockRHP4Client::new());
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
                    good_for_upload: true,
                })
                .collect(),
        );

        let uploader = MockUploader::new(hosts.clone(), transport.clone(), app_key.clone());
        let downloader = MockDownloader::new(hosts.clone(), transport.clone(), app_key.clone());

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
        let transport = Arc::new(MockRHP4Client::new());
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
                    good_for_upload: true,
                })
                .collect(),
        );

        let uploader = MockUploader::new(hosts.clone(), transport.clone(), app_key.clone());
        let downloader = MockDownloader::new(hosts.clone(), transport.clone(), app_key.clone());

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
        let transport = Arc::new(MockRHP4Client::new());
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
                    good_for_upload: true,
                })
                .collect(),
        );

        let uploader = MockUploader::new(hosts.clone(), transport.clone(), app_key.clone());
        let downloader = MockDownloader::new(hosts.clone(), transport.clone(), app_key.clone());

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
        use sia::rhp::SECTOR_SIZE;
        const SEGMENT_SIZE: u64 = 64; // leaf size

        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let transport = Arc::new(MockRHP4Client::new());
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
                    good_for_upload: true,
                })
                .collect(),
        );

        let uploader = MockUploader::new(hosts.clone(), transport.clone(), app_key.clone());
        let downloader = MockDownloader::new(hosts.clone(), transport.clone(), app_key.clone());

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
        let transport = Arc::new(MockRHP4Client::new());
        let hosts = Hosts::new();

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
                        protocol: sia::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                })
                .collect(),
        );

        let uploader = MockUploader::new(hosts.clone(), transport.clone(), app_key.clone());
        let downloader = MockDownloader::new(hosts.clone(), transport.clone(), app_key.clone());

        let input: Bytes = Bytes::from("Hello, world!");

        let object = uploader
            .upload(Cursor::new(input.clone()), UploadOptions::default())
            .await
            .expect("upload to complete");

        // make all hosts slow
        transport.set_slow_hosts(
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
        let transport = Arc::new(MockRHP4Client::new());
        let hosts = Hosts::new();

        let uploader = MockUploader::new(hosts.clone(), transport.clone(), app_key.clone());

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
        let transport = Arc::new(MockRHP4Client::new());
        let hosts = Hosts::new();

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
                        protocol: sia::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                })
                .collect(),
        );

        // make the 1st host slow
        transport.set_slow_hosts(
            host_keys.iter().take(1).copied(),
            tokio::time::Duration::from_secs(2),
        );

        let uploader = MockUploader::new(hosts.clone(), transport.clone(), app_key.clone());

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
        let transport = Arc::new(MockRHP4Client::new());
        let hosts = Hosts::new();

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
                        protocol: sia::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                })
                .collect(),
        );

        // Make all hosts slow
        transport.set_slow_hosts(host_keys.iter().take(30).copied(), Duration::from_secs(2));

        let uploader = MockUploader::new(hosts.clone(), transport.clone(), app_key.clone());

        let input: Bytes = Bytes::from("Hello, world!");

        let _ = uploader
            .upload(Cursor::new(input.clone()), UploadOptions::default())
            .await
            .expect("upload to succeed");
    }

    #[tokio::test]
    async fn test_upload_not_enough_hosts_good_for_upload() {
        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
        let transport = Arc::new(MockRHP4Client::new());
        let hosts = Hosts::new();

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
                        protocol: sia::types::v2::Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: i < 10,
                })
                .collect(),
        );

        let uploader = MockUploader::new(hosts.clone(), transport.clone(), app_key.clone());

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
