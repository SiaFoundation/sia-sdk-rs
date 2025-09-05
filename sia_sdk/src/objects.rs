use std::collections::VecDeque;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use log::debug;
use thiserror::Error;
use tokio::io::{AsyncReadExt, BufReader, BufWriter};
use tokio::select;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio::time::error::Elapsed;

use crate::objects::encryption::{encrypt_shard, encrypt_shards};
use crate::objects::erasure_coding::ErasureCoder;
use crate::objects::slabs::{Sector, Slab};
use crate::rhp::{self, Host, SEGMENT_SIZE};
use crate::signing::{PrivateKey, PublicKey};
use crate::types::Hash256;

use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, timeout};

pub mod encryption;
pub mod erasure_coding;
pub mod slabs;

pub trait HostDialer: Clone + Send + Sync {
    type Error: From<Error> + Debug + Send;

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

    #[error("timeout error: {0}")]
    Timeout(#[from] Elapsed),
}

/// A thread-safe queue of host public keys.
#[derive(Debug, Clone)]
struct HostQueue(Arc<Mutex<VecDeque<PublicKey>>>);

impl HostQueue {
    pub fn new(hosts: Vec<PublicKey>) -> Self {
        Self(Arc::new(Mutex::new(VecDeque::from(hosts))))
    }

    pub fn pop_front(&self) -> Result<PublicKey, Error> {
        self.0
            .lock()
            .map_err(|_| Error::Closed)?
            .pop_front()
            .ok_or(Error::NoMoreHosts)
    }

    pub fn retry(&self, host: PublicKey) -> Result<(), Error> {
        self.0.lock().map_err(|_| Error::Closed)?.push_back(host);
        Ok(())
    }
}

pub struct Uploader<D: HostDialer> {
    account_key: PrivateKey,
    max_inflight: usize,

    dialer: D,
}

impl<D: HostDialer> Uploader<D>
where
    D: HostDialer + 'static,
    D::Error: From<Error> + Send,
{
    pub fn new(dialer: D, account_key: PrivateKey, max_inflight: usize) -> Self {
        Uploader {
            account_key,
            max_inflight,
            dialer,
        }
    }

    async fn upload_shard(
        dialer: D,
        hosts: HostQueue,
        account_key: PrivateKey,
        data: Bytes,
        write_timeout: Duration,
    ) -> Result<Sector, D::Error> {
        let host_key = hosts.pop_front()?;
        let root = timeout(
            write_timeout,
            dialer.write_sector(host_key, &account_key, data),
        )
        .await
        .map_err(|e| Error::Timeout(e).into())
        .and_then(|res| res)
        .inspect_err(|_| {
            debug!("upload to {host_key} failed, retrying");
            let _ = hosts.retry(host_key);
        })?;

        Ok(Sector { root, host_key })
    }

    async fn upload_slab_shard(
        _permit: OwnedSemaphorePermit,
        dialer: D,
        hosts: HostQueue,
        account_key: PrivateKey,
        data: Bytes,
        slab_index: usize,
        shard_index: usize,
    ) -> Result<(usize, usize, Sector), D::Error> {
        const BACKOFF_MULTIPLIER: u32 = 2;

        let initial_timeout = Duration::from_secs(10);
        let mut tasks = JoinSet::new();
        tasks.spawn(Self::upload_shard(
            dialer.clone(),
            hosts.clone(),
            account_key.clone(),
            data.clone(),
            initial_timeout,
        ));
        let mut attempts = 0;
        loop {
            let timeout = initial_timeout * BACKOFF_MULTIPLIER.pow(attempts);
            tokio::select! {
                Some(res) = tasks.join_next() => {
                    match res.unwrap() {
                        Ok(sector) => {
                            debug!("slab {slab_index} shard {shard_index} uploaded");
                            return Ok((slab_index, shard_index, sector));
                        }
                        Err(e) => {
                            debug!("slab {slab_index} shard {shard_index} upload failed {e:?}");
                            if tasks.is_empty() {
                                tasks.spawn(Self::upload_shard(dialer.clone(), hosts.clone(), account_key.clone(), data.clone(), timeout));
                            }
                        }
                    }
                },
                _ = tokio::time::sleep(timeout / 2) => {
                    debug!("racing slow host for slab {slab_index} shard {shard_index}");
                    tasks.spawn(Self::upload_shard(dialer.clone(), hosts.clone(), account_key.clone(), data.clone(), timeout));
                }
            }
            attempts += 1;
        }
    }

    /// Reads until EOF and uploads all slabs.
    /// The data will be erasure coded, encrypted,
    /// and uploaded using the uploader's parameters.
    pub async fn upload<R: AsyncReadExt + Unpin + Send + 'static>(
        &self,
        mut r: R,
        encryption_key: [u8; 32],
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Vec<Slab>, D::Error> {
        let (tx, mut rx) = mpsc::channel(1);

        let semaphore = Arc::new(Semaphore::new(self.max_inflight));
        // use a buffered reader since the erasure coder reads 64 bytes at a time.
        let mut sector_jobs = JoinSet::new();
        let mut slabs = Vec::new();
        let dialer = self.dialer.clone();

        tokio::spawn(async move {
            let mut r = BufReader::new(&mut r);
            let mut rs = ErasureCoder::new(data_shards as usize, parity_shards as usize).unwrap();
            loop {
                match rs.read_encoded_shards(&mut r).await {
                    Ok((shards, length)) => {
                        if length == 0 {
                            break;
                        }
                        let _ = tx.send(Ok((shards, length))).await;
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e.into())).await;
                    }
                }
            }
            drop(tx);
        });

        loop {
            select! {
                Some(res) = rx.recv() => {
                    let (mut shards, length) = res?;
                    let slab_index = slabs.len();
                    let slab = Slab {
                        sectors: vec![Sector { root: Hash256::default(), host_key: PublicKey::new([0u8; 32]) }; shards.len()],
                        encryption_key,
                        offset: 0,
                        length,
                        min_shards: data_shards,
                    };
                    slabs.push(slab);
                    encrypt_shards(&encryption_key, &mut shards, 0);
                    debug!("slab {slab_index} encrypted, uploading shards");
                    let hosts = HostQueue::new(dialer.hosts());
                    for (shard_index, shard) in shards.into_iter().enumerate() {
                        let permit = semaphore.clone().acquire_owned().await.map_err(|_| Error::Closed)?;
                        sector_jobs.spawn(Self::upload_slab_shard(permit, dialer.clone(), hosts.clone(), self.account_key.clone(), shard.into(), slab_index, shard_index));
                    }
                },
                Some(res) = sector_jobs.join_next() => {
                    let (slab_index, shard_index, sector) = res.map_err(|_| Error::Closed)??;
                    slabs[slab_index].sectors[shard_index] = sector;
                },
                else => break
            }
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
                        Err(e) => {
                            debug!("sector download failed {:?}", e);
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
                _ = sleep(Duration::from_secs(4)) => {
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
    use std::io::Cursor;

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
                Cursor::new(data.clone()),
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
                Cursor::new(data.clone()),
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
