use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use futures::future::try_join_all;
use futures::stream::FuturesUnordered;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::objects::encryption::encrypt_shards;
use crate::objects::erasure_coding::{self, ErasureCoder};
use crate::objects::slabs::{Sector, Slab};
use crate::rhp::{self, Host};
use crate::signing::{PrivateKey, PublicKey};
use crate::types::Hash256;

pub trait HostDialer: Send + Sync {
    type Error: From<UploadError> + Send;

    fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Vec<u8>,
    ) -> impl Future<Output = Result<Hash256, Self::Error>> + Send;

    fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send;

    fn hosts(&self) -> Vec<PublicKey>;
    fn update_hosts(&mut self, hosts: Vec<Host>);
}

#[derive(Debug, Error)]
pub enum UploadError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("RHP error: {0}")]
    RPC(#[from] rhp::Error),

    #[error("encoder error: {0}")]
    Encoder(#[from] erasure_coding::Error),
    #[error("not enough shards: {0}/{1}")]
    NotEnoughShards(u8, u8),

    #[error("no more hosts available")]
    NoMoreHosts,
    #[error("uploader closed")]
    Closed,
}

struct UploaderInner<D: HostDialer> {
    account_key: PrivateKey,

    dialer: D,
    semaphore: Semaphore, // for limiting concurrent uploads
}

impl<D: HostDialer> UploaderInner<D>
where
    D::Error: From<UploadError>,
{
    async fn try_upload_sector(
        &self,
        host_queue: HostQueue,
        sector: Vec<u8>,
    ) -> Result<Sector, D::Error> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| UploadError::Closed)?;

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
        sector: impl AsRef<[u8]>,
    ) -> Result<Sector, D::Error> {
        let mut tasks = FuturesUnordered::new();
        tasks.push(self.try_upload_sector(host_queue.clone(), sector.as_ref().to_vec()));
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
                                tasks.push(self.try_upload_sector(host_queue.clone(), sector.as_ref().to_vec()));
                            }
                        }
                    }
                },
                _ = tokio::time::sleep(Duration::from_secs(15)) => {
                    // race another host to prevent slow hosts from stalling uploads
                    tasks.push(self.try_upload_sector(host_queue.clone(), sector.as_ref().to_vec()));
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
    D::Error: From<UploadError> + From<erasure_coding::Error>,
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
        shards: Vec<Vec<u8>>,
    ) -> Result<Vec<Sector>, D::Error>
    where
        D::Error: From<UploadError>,
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
        shards: Vec<Vec<u8>>,
        encryption_key: [u8; 32],
        data_shards: u8,
        length: usize,
    ) -> Result<Option<Slab>, D::Error> {
        if shards.len() < data_shards as usize {
            return Err(UploadError::NotEnoughShards(shards.len() as u8, data_shards).into());
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
        let mut rs = ErasureCoder::new(data_shards as usize, parity_shards as usize)?;
        let mut sector_jobs = JoinSet::new();
        let mut slabs = Vec::new();
        loop {
            let (mut shards, length) = rs.read_encoded_shards(r).await?;
            if length == 0 {
                break;
            }
            let inner = self.inner.clone();
            let index = slabs.len();
            sector_jobs.spawn(async move {
                encrypt_shards(&encryption_key, &mut shards, 0);
                Self::try_upload_shards(inner, shards)
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

#[derive(Debug)]
struct HostQueueInner {
    queue: VecDeque<PublicKey>,
    failures: HashMap<PublicKey, usize>,
    max_attempts: usize,
}

/// A thread-safe queue of host public keys.
#[derive(Debug, Clone)]
pub struct HostQueue {
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
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().queue.is_empty()
    }

    pub fn pop_front(&self) -> Result<PublicKey, UploadError> {
        self.inner
            .lock()
            .unwrap()
            .queue
            .pop_front()
            .ok_or(UploadError::NoMoreHosts)
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

#[cfg(test)]
mod test {
    use crate::rhp::{SECTOR_SIZE, sector_root};
    use rand::RngCore;
    use std::collections::HashMap;
    use std::io::Cursor;

    use super::*;

    struct MockUploader {
        hosts: Mutex<HashMap<PublicKey, Host>>,
        sectors: Mutex<HashMap<Hash256, Vec<u8>>>,
    }

    impl MockUploader {
        fn new() -> Self {
            Self {
                hosts: Mutex::new(HashMap::new()),
                sectors: Mutex::new(HashMap::new()),
            }
        }
    }

    impl HostDialer for MockUploader {
        type Error = UploadError;

        async fn write_sector(
            &self,
            host_key: PublicKey,
            _: &PrivateKey,
            data: Vec<u8>,
        ) -> Result<Hash256, Self::Error> {
            let host_exists = {
                let hosts = self.hosts.lock().unwrap();
                hosts.contains_key(&host_key)
            };
            if !host_exists {
                return Err(UploadError::NoMoreHosts);
            }
            let root = sector_root(data.as_ref());
            self.sectors.lock().unwrap().insert(root, data);
            Ok(root)
        }

        async fn read_sector(
            &self,
            host_key: PublicKey,
            _: &PrivateKey,
            root: Hash256,
            offset: usize,
            limit: usize,
        ) -> Result<Vec<u8>, Self::Error> {
            let host_exists = {
                let hosts = self.hosts.lock().unwrap();
                hosts.contains_key(&host_key)
            };
            if !host_exists {
                return Err(UploadError::NoMoreHosts);
            }
            let sectors = self.sectors.lock().unwrap();
            if let Some(data) = sectors.get(&root) {
                Ok(data[offset..offset + limit].to_vec())
            } else {
                Err(rhp::Error::RPC(rhp::RPCError {
                    code: 3,
                    description: "sector not found".into(),
                })
                .into())
            }
        }

        fn hosts(&self) -> Vec<PublicKey> {
            self.hosts.lock().unwrap().keys().cloned().collect()
        }

        fn update_hosts(&mut self, hosts: Vec<Host>) {
            let mut hosts_map = self.hosts.lock().unwrap();
            hosts_map.clear();
            for host in hosts {
                hosts_map.insert(host.public_key, host);
            }
        }
    }

    #[tokio::test]
    async fn test_upload() {
        const DATA_SHARDS: usize = 2;
        const PARITY_SHARDS: usize = 2;

        let mut uploader = MockUploader::new();
        let seed: [u8; 32] = rand::random();
        let account_key = PrivateKey::from_seed(&seed);

        uploader.update_hosts(vec![
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

        let slab_uploader = Uploader::new(uploader, account_key, 10);

        let mut data = vec![0u8; SECTOR_SIZE * DATA_SHARDS];
        rand::rng().fill_bytes(&mut data);
        let mut r = Cursor::new(data.clone());

        let encryption_key = rand::random();
        let slabs = slab_uploader
            .upload(
                &mut r,
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
    }
}
