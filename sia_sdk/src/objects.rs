use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use futures::future::try_join_all;
use futures::stream::FuturesUnordered;
use thiserror::Error;
use tokio::io::{AsyncReadExt, BufReader, BufWriter};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::objects::encryption::{encrypt_shard, encrypt_shards};
use crate::objects::erasure_coding::ErasureCoder;
use crate::objects::slabs::{Sector, Slab};
use crate::rhp::{self, Host, SEGMENT_SIZE};
use crate::signing::{PrivateKey, PublicKey};
use crate::types::Hash256;

use tokio::io::AsyncWriteExt;
use tokio::time::sleep;

pub mod encryption;
pub mod erasure_coding;
pub mod slabs;

pub trait HostDialer: Send + Sync {
    type Error: From<Error> + Send;

    fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> impl Future<Output = Result<Hash256, Self::Error>> + Send;

    fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        limit: usize,
    ) -> impl Future<Output = Result<Bytes, Self::Error>> + Send;

    fn hosts(&self) -> Vec<PublicKey>;
    fn update_hosts(&mut self, hosts: Vec<Host>);
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("RHP error: {0}")]
    RPC(#[from] rhp::Error),

    #[error("encoder error: {0}")]
    Encoder(#[from] erasure_coding::Error),
    #[error("not enough shards: {0}/{1}")]
    NotEnoughShards(u8, u8),

    #[error("invalid range: {0}-{1}")]
    OutOfRange(usize, usize),
    #[error("no more hosts available")]
    NoMoreHosts,
    #[error("uploader closed")]
    Closed,
}

#[derive(Debug)]
struct HostQueueInner {
    queue: VecDeque<PublicKey>,
    failures: HashMap<PublicKey, usize>,
    max_attempts: usize,
}

/// A thread-safe queue of host public keys.
#[derive(Debug, Clone)]
struct HostQueue {
    inner: Arc<Mutex<HostQueueInner>>,
}

impl HostQueue {
    pub fn new(hosts: Vec<PublicKey>, max_attempts: usize) -> Self {
        HostQueue {
            inner: Arc::new(Mutex::new(HostQueueInner {
                queue: VecDeque::from(hosts),
                failures: HashMap::new(),
                max_attempts,
            })),
        }
    }

    pub fn pop_front(&self) -> Result<PublicKey, Error> {
        self.inner
            .lock()
            .unwrap()
            .queue
            .pop_front()
            .ok_or(Error::NoMoreHosts)
    }

    pub fn retry(&self, host: PublicKey) {
        let mut inner = self.inner.lock().unwrap();
        let max_attempts = inner.max_attempts;
        let attempts = inner.failures.entry(host).or_insert(0);
        if *attempts < max_attempts {
            *attempts += 1;
            inner.queue.push_back(host);
        }
    }
}

struct UploaderInner<D: HostDialer> {
    account_key: PrivateKey,

    dialer: D,
    semaphore: Semaphore, // for limiting concurrent uploads
}

impl<D: HostDialer> UploaderInner<D>
where
    D::Error: From<Error>,
{
    async fn try_upload_sector(
        &self,
        host_queue: HostQueue,
        sector: Bytes,
    ) -> Result<Sector, D::Error> {
        let _permit = self.semaphore.acquire().await.map_err(|_| Error::Closed)?;

        let host_key = host_queue.pop_front()?;

        match self
            .dialer
            .write_sector(host_key, &self.account_key, sector)
            .await
        {
            Ok(root) => Ok(Sector { root, host_key }),
            Err(err) => {
                host_queue.retry(host_key);
                Err(err)
            }
        }
    }

    async fn upload_slab_sector(
        &self,
        host_queue: HostQueue,
        sector: Bytes,
    ) -> Result<Sector, D::Error> {
        let mut tasks = FuturesUnordered::new();
        tasks.push(self.try_upload_sector(host_queue.clone(), sector.clone()));
        loop {
            tokio::select! {
                Some(res) = tasks.next() => {
                    match res {
                        Ok(sector) => {
                            return Ok(sector);
                        }
                        Err(_) => {
                            if tasks.is_empty() {
                                // try the next host
                                tasks.push(self.try_upload_sector(host_queue.clone(), sector.clone()));
                            }
                        }
                    }
                },
                _ = tokio::time::sleep(Duration::from_secs(15)) => {
                    // race another host to prevent slow hosts from stalling uploads
                    tasks.push(self.try_upload_sector(host_queue.clone(), sector.clone()));
                }
            }
        }
    }
}

pub struct Uploader<D: HostDialer> {
    inner: Arc<UploaderInner<D>>,
}

impl<D: HostDialer> Uploader<D>
where
    D: HostDialer + 'static,
    D::Error: From<Error>,
{
    pub fn new(dialer: D, account_key: PrivateKey, max_inflight: usize) -> Self {
        let semaphore = Semaphore::new(max_inflight);
        Uploader {
            inner: Arc::new(UploaderInner {
                account_key,
                dialer,
                semaphore,
            }),
        }
    }

    /// helper to upload shards. A function that does not
    /// take `self` is necessary for tokio::spawn
    async fn try_upload_shards(
        uploader: Arc<UploaderInner<D>>,
        shards: Vec<Bytes>,
    ) -> Result<Vec<Sector>, D::Error>
    where
        D::Error: From<Error>,
    {
        let hosts = HostQueue::new(uploader.dialer.hosts(), 2);
        let mut futures = Vec::new();
        for shard in shards {
            futures.push(uploader.upload_slab_sector(hosts.clone(), shard));
        }

        try_join_all(futures).await
    }

    /// Uploads the erasure coded shards. The shards
    /// should be encrypted by the caller.
    ///
    /// [upload] should generally be preferred for simplicity.
    /// This is primarily useful for environments that have
    /// special concurrency requirements.
    pub async fn upload_shards<R: AsyncReadExt + Unpin>(
        &self,
        shards: Vec<Bytes>,
        encryption_key: [u8; 32],
        data_shards: u8,
        length: usize,
    ) -> Result<Option<Slab>, D::Error> {
        if shards.len() < data_shards as usize {
            return Err(Error::NotEnoughShards(shards.len() as u8, data_shards).into());
        }
        let sectors = Self::try_upload_shards(self.inner.clone(), shards).await?;
        let slab = Slab {
            encryption_key,
            min_shards: data_shards,
            sectors,
            offset: 0,
            length,
        };
        Ok(Some(slab))
    }

    /// Reads until EOF and uploads all slabs.
    /// The data will be erasure coded, encrypted,
    /// and uploaded using the uploader's parameters.
    pub async fn upload<R: AsyncReadExt + Unpin>(
        &self,
        r: &mut R,
        encryption_key: [u8; 32],
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Vec<Slab>, D::Error> {
        // use a buffered reader since the erasure coder reads 64 bytes at a time.
        let mut r = BufReader::new(r);
        let mut rs = ErasureCoder::new(data_shards as usize, parity_shards as usize)
            .map_err(|e| e.into())?;
        let mut sector_jobs = JoinSet::new();
        let mut slabs = Vec::new();
        loop {
            let (mut shards, length) =
                rs.read_encoded_shards(&mut r).await.map_err(|e| e.into())?;
            if length == 0 {
                break;
            }
            let inner = self.inner.clone();
            let index = slabs.len();
            sector_jobs.spawn(async move {
                encrypt_shards(&encryption_key, &mut shards, 0);
                Self::try_upload_shards(inner, shards.drain(..).map(Bytes::from).collect())
                    .await
                    .map(|sectors| (index, sectors))
            });
            slabs.push(Slab {
                encryption_key,
                min_shards: data_shards,
                sectors: vec![],
                offset: 0,
                length,
            });
        }

        while let Some(res) = sector_jobs.join_next().await {
            let (i, sectors) = res.unwrap()?;
            slabs[i].sectors = sectors;
        }
        Ok(slabs)
    }
}

pub struct Downloader<D: HostDialer> {
    account_key: PrivateKey,

    dialer: D,
    semaphore: Semaphore,
}

impl<D: HostDialer> Downloader<D>
where
    D::Error: From<Error>,
{
    pub fn new(dialer: D, account_key: PrivateKey, max_inflight: usize) -> Self {
        let semaphore = Semaphore::new(max_inflight);
        Self {
            account_key,
            dialer,
            semaphore,
        }
    }

    // helper to pair a sector with its erasure-coded index.
    // Required because [FuturesUnordered.push] does not
    // preserve ordering and doesn't play nice with closures.
    async fn try_download_sector(
        &self,
        host_key: PublicKey,
        root: Hash256,
        offset: usize,
        limit: usize,
        index: usize,
    ) -> Result<(usize, Vec<u8>), D::Error> {
        let _permit = self.semaphore.acquire().await.map_err(|_| Error::Closed)?;
        let data = self
            .dialer
            .read_sector(host_key, &self.account_key, root, offset, limit)
            .await?;
        Ok((index, data.to_vec()))
    }

    /// Downloads the shards of an erasure-coded slab.
    /// Successful shards will be decrypted using the
    /// encryption_key.
    ///
    /// offset and limit are the byte range to download
    /// from each sector.
    pub async fn download_slab_shards(
        &self,
        encryption_key: &[u8; 32],
        sectors: &[Sector],
        min_shards: u8,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<Option<Vec<u8>>>, Error> {
        let (data_shards, parity_shards) = sectors.split_at(min_shards as usize);

        let mut download_tasks = FuturesUnordered::new();
        for (i, sector) in data_shards.iter().enumerate() {
            download_tasks.push(self.try_download_sector(
                sector.host_key,
                sector.root,
                offset,
                limit,
                i,
            ));
        }

        let mut parity_shards = VecDeque::from(
            parity_shards
                .iter()
                .enumerate()
                .map(|(i, sector)| (i + data_shards.len(), sector))
                .collect::<Vec<_>>(),
        );
        let mut successful: u8 = 0;
        let mut shards = vec![None; sectors.len()];
        loop {
            tokio::select! {
                Some(res) = download_tasks.next() => {
                    match res {
                        Ok((index, mut data)) => {
                            encrypt_shard(encryption_key, &mut data, index as u8, offset);
                            shards[index] = Some(data);
                            successful += 1;
                            if successful >= min_shards {
                               return Ok(shards);
                            }
                        }
                        Err(_) => {
                            let rem = min_shards.saturating_sub(successful);
                            if rem == 0 {
                                return Ok(shards); // sanity check
                            } else if download_tasks.len() <= rem as usize && let Some((i, sector)) = parity_shards.pop_front() {
                                // only spawn additional download tasks if there are not
                                // enough to satisfy the required number of shards. The
                                // sleep arm will handle slow hosts.
                                download_tasks.push(self.try_download_sector(
                                    sector.host_key,
                                    sector.root,
                                    offset,
                                    limit,
                                    i,
                                ));
                            } else if download_tasks.is_empty() && successful < min_shards {
                                return Err(Error::NotEnoughShards(successful, min_shards));
                            }
                        }
                    }
                },
                _ = sleep(Duration::from_secs(10)) => {
                    if let Some((i, sector)) = parity_shards.pop_front(){
                        download_tasks.push(self.try_download_sector(
                            sector.host_key,
                            sector.root,
                            offset,
                            limit,
                            i,
                        ));
                    }
                }
            }
        }
    }

    /// Returns the offset and length of the sector to download in order
    /// to recover the raw data.
    fn sector_region(data_shards: usize, offset: usize, length: usize) -> (usize, usize) {
        let chunk_size = SEGMENT_SIZE * data_shards;
        let start = (offset / chunk_size) * SEGMENT_SIZE;
        let end = (offset + length).div_ceil(chunk_size) * SEGMENT_SIZE;
        (start, end - start)
    }

    pub async fn download_range<W: AsyncWriteExt + Unpin>(
        &self,
        w: &mut W,
        slabs: &[Slab],
        mut offset: usize,
        mut length: usize,
    ) -> Result<(), Error> {
        let max_length = slabs.iter().fold(0, |sum, slab| sum + slab.length);
        if offset + length > max_length {
            return Err(Error::OutOfRange(offset, length));
        } else if length == 0 {
            return Ok(());
        }
        let mut w = BufWriter::new(w);
        for slab in slabs {
            if length == 0 {
                break;
            }
            let n = slab.length - slab.offset;
            if offset >= n {
                offset -= n;
                continue;
            }

            let slab_offset = slab.offset + offset;
            offset = 0;

            let slab_length = (slab.length - slab_offset).min(length);
            let (shard_offset, shard_length) =
                Self::sector_region(slab.min_shards as usize, slab_offset, slab_length);
            let mut shards = self
                .download_slab_shards(
                    &slab.encryption_key,
                    &slab.sectors,
                    slab.min_shards,
                    shard_offset,
                    shard_length,
                )
                .await?;
            let mut rs = ErasureCoder::new(
                slab.min_shards as usize,
                slab.sectors.len() - slab.min_shards as usize,
            )?;
            rs.write_reconstructed_shards(
                &mut w,
                &mut shards,
                slab_offset % (SEGMENT_SIZE * slab.min_shards as usize),
                slab_length,
            )
            .await?;
            length -= slab_length;
        }
        w.flush().await?;
        Ok(())
    }

    /// downloads data from the provided slabs and writes it
    /// to the writer.
    pub async fn download<W: AsyncWriteExt + Unpin>(
        &self,
        w: &mut W,
        slabs: &[Slab],
    ) -> Result<(), Error> {
        let total_length = slabs.iter().fold(0, |sum, slab| sum + slab.length);
        self.download_range(w, slabs, 0, total_length).await
    }
}

#[cfg(test)]
mod test {
    use crate::objects::Downloader;
    use crate::rhp::{SECTOR_SIZE, sector_root};
    use rand::RngCore;
    use std::collections::HashMap;

    use super::*;

    #[derive(Debug)]
    struct MockDialerInner {
        hosts: Mutex<HashMap<PublicKey, Host>>,
        sectors: Mutex<HashMap<Hash256, Bytes>>,
    }

    #[derive(Debug, Clone)]
    struct MockDialer {
        inner: Arc<MockDialerInner>,
    }

    impl MockDialer {
        fn new() -> Self {
            Self {
                inner: Arc::new(MockDialerInner {
                    hosts: Mutex::new(HashMap::new()),
                    sectors: Mutex::new(HashMap::new()),
                }),
            }
        }
    }

    impl HostDialer for MockDialer {
        type Error = Error;

        async fn write_sector(
            &self,
            host_key: PublicKey,
            _: &PrivateKey,
            data: Bytes,
        ) -> Result<Hash256, Self::Error> {
            let host_exists = {
                let hosts = self.inner.hosts.lock().unwrap();
                hosts.contains_key(&host_key)
            };
            if !host_exists {
                return Err(Error::NoMoreHosts);
            }
            let root = sector_root(data.as_ref());
            self.inner.sectors.lock().unwrap().insert(root, data);
            Ok(root)
        }

        async fn read_sector(
            &self,
            host_key: PublicKey,
            _: &PrivateKey,
            root: Hash256,
            offset: usize,
            limit: usize,
        ) -> Result<Bytes, Self::Error> {
            let host_exists = {
                let hosts = self.inner.hosts.lock().unwrap();
                hosts.contains_key(&host_key)
            };
            if !host_exists {
                return Err(Error::NoMoreHosts);
            }
            let sectors = self.inner.sectors.lock().unwrap();
            if let Some(data) = sectors.get(&root) {
                Ok(data[offset..offset + limit].to_vec().into())
            } else {
                Err(rhp::Error::RPC(rhp::RPCError {
                    code: 3,
                    description: "sector not found".into(),
                })
                .into())
            }
        }

        fn hosts(&self) -> Vec<PublicKey> {
            self.inner.hosts.lock().unwrap().keys().cloned().collect()
        }

        fn update_hosts(&mut self, hosts: Vec<Host>) {
            let mut hosts_map = self.inner.hosts.lock().unwrap();
            hosts_map.clear();
            for host in hosts {
                hosts_map.insert(host.public_key, host);
            }
        }
    }

    #[tokio::test]
    async fn test_roundtrip() {
        const DATA_SHARDS: usize = 2;
        const PARITY_SHARDS: usize = 2;

        let mut dialer = MockDialer::new();
        let seed: [u8; 32] = rand::random();
        let account_key = PrivateKey::from_seed(&seed);

        dialer.update_hosts(vec![
            Host {
                public_key: PublicKey::new(rand::random()),
                addresses: vec![],
            },
            Host {
                public_key: PublicKey::new(rand::random()),
                addresses: vec![],
            },
            Host {
                public_key: PublicKey::new(rand::random()),
                addresses: vec![],
            },
            Host {
                public_key: PublicKey::new(rand::random()),
                addresses: vec![],
            },
        ]);

        let slab_uploader = Uploader::new(dialer.clone(), account_key.clone(), 10);

        let mut data = vec![0u8; SECTOR_SIZE * DATA_SHARDS];
        rand::rng().fill_bytes(&mut data);

        let encryption_key = rand::random();
        let slabs = slab_uploader
            .upload(
                &mut &data[..],
                encryption_key,
                DATA_SHARDS as u8,
                PARITY_SHARDS as u8,
            )
            .await
            .expect("upload failed");

        assert_eq!(slabs[0].encryption_key, encryption_key);
        assert_eq!(
            slabs[0].sectors.len(),
            DATA_SHARDS as usize + PARITY_SHARDS as usize
        );
        assert_eq!(slabs[0].length, data.len());

        let slab_downloader = Downloader::new(dialer.clone(), account_key.clone(), 10);
        let mut downloaded_data = Vec::with_capacity(data.len());
        slab_downloader
            .download(&mut downloaded_data, &slabs)
            .await
            .expect("failed to download");

        assert_eq!(downloaded_data.len(), data.len());
        assert_eq!(downloaded_data, data);
    }

    #[tokio::test]
    async fn test_download_range() {
        const DATA_SHARDS: usize = 2;
        const PARITY_SHARDS: usize = 2;
        const SLAB_SIZE: usize = SECTOR_SIZE * DATA_SHARDS;
        const DATA_SIZE: usize = 4 * SLAB_SIZE;

        let mut dialer = MockDialer::new();
        let seed: [u8; 32] = rand::random();
        let account_key = PrivateKey::from_seed(&seed);

        dialer.update_hosts(vec![
            Host {
                public_key: PublicKey::new(rand::random()),
                addresses: vec![],
            },
            Host {
                public_key: PublicKey::new(rand::random()),
                addresses: vec![],
            },
            Host {
                public_key: PublicKey::new(rand::random()),
                addresses: vec![],
            },
            Host {
                public_key: PublicKey::new(rand::random()),
                addresses: vec![],
            },
        ]);

        let slab_uploader = Uploader::new(dialer.clone(), account_key.clone(), 10);

        let mut data = vec![0u8; DATA_SIZE];
        rand::rng().fill_bytes(&mut data);

        let encryption_key = rand::random();
        let slabs = slab_uploader
            .upload(
                &mut &data[..],
                encryption_key,
                DATA_SHARDS as u8,
                PARITY_SHARDS as u8,
            )
            .await
            .expect("upload failed");

        assert_eq!(slabs[0].encryption_key, encryption_key);
        assert_eq!(
            slabs[0].sectors.len(),
            DATA_SHARDS as usize + PARITY_SHARDS as usize
        );
        assert_eq!(slabs.len(), 4);

        let slab_downloader = Downloader::new(dialer.clone(), account_key.clone(), 10);
        let mut downloaded_data = Vec::with_capacity(data.len());

        slab_downloader
            .download_range(&mut downloaded_data, &slabs, 0, 100)
            .await
            .expect("failed to download");
        assert_eq!(downloaded_data.len(), 100);
        assert_eq!(&downloaded_data, &data[..100]);
        downloaded_data.clear();

        slab_downloader
            .download_range(&mut downloaded_data, &slabs, 100, 100)
            .await
            .expect("failed to download");

        assert_eq!(downloaded_data.len(), 100);
        assert_eq!(&downloaded_data, &data[100..200]);
        downloaded_data.clear();

        // across slab boundaries
        let offset = SLAB_SIZE - 50;
        slab_downloader
            .download_range(&mut downloaded_data, &slabs, offset, 100)
            .await
            .expect("failed to download");

        assert_eq!(downloaded_data.len(), 100);
        assert_eq!(&downloaded_data, &data[offset..offset + 100]);
        downloaded_data.clear();

        // eof
        let offset = DATA_SIZE - 100;
        slab_downloader
            .download_range(&mut downloaded_data, &slabs, offset, 100)
            .await
            .expect("failed to download");
        assert_eq!(downloaded_data.len(), 100);
        assert_eq!(&downloaded_data, &data[offset..offset + 100]);
        downloaded_data.clear();

        // length out of range
        let offset = DATA_SIZE - 100;
        slab_downloader
            .download_range(&mut downloaded_data, &slabs, offset, 200)
            .await
            .expect_err("download should fail");

        // offset out of range
        let offset = DATA_SIZE + 100;
        slab_downloader
            .download_range(&mut downloaded_data, &slabs, offset, 200)
            .await
            .expect_err("download should fail");
    }
}
