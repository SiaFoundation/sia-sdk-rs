use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::debug;
use sia::encryption::{EncryptionKey, encrypt_shard};
use sia::erasure_coding::{self, ErasureCoder};
use sia::rhp::SEGMENT_SIZE;
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinSet, spawn_blocking};
use tokio::time::error::Elapsed;
use tokio::time::sleep;

use crate::app_client::{self, Client as AppClient, HostQuery};
use crate::quic::client::Client;
use crate::{Object, Sector, SharedObject, Slab, quic};

/// A SlabIterator can be used to iterate over slabs to be downloaded.
/// This is used to abstract over different sources of slabs, such as
/// a pre-fetched list of slabs, or fetching slabs on-demand from the
/// indexer.
pub trait SlabIterator {
    type Error: Debug;

    fn next(&mut self) -> impl Future<Output = Result<Option<Slab>, Self::Error>>;
    fn max_length(&self) -> usize;
}

impl SlabIterator for VecDeque<Slab> {
    type Error = ();

    async fn next(&mut self) -> Result<Option<Slab>, Self::Error> {
        Ok(self.pop_front())
    }

    fn max_length(&self) -> usize {
        self.iter().fold(0, |sum, slab| sum + slab.length as usize)
    }
}

struct SlabFetchCache {
    cache: Mutex<HashMap<Hash256, Slab>>,
    app_client: AppClient,
    app_key: PrivateKey,
}

impl SlabFetchCache {
    async fn slab(&self, slab_slice: &Slab) -> Result<Option<Slab>, app_client::Error> {
        let slab_id = slab_slice.digest();
        if let Some(slab) = {
            let cache = self
                .cache
                .lock()
                .map_err(|_| app_client::Error::Custom("failed to lock mutex".into()))?;
            cache.get(&slab_id).cloned()
        } {
            return Ok(Some(slab));
        }

        let slab = self.app_client.slab(&self.app_key, &slab_id).await?;
        let slab = Slab {
            encryption_key: slab.encryption_key,
            min_shards: slab.min_shards,
            sectors: slab.sectors,
            offset: slab_slice.offset,
            length: slab_slice.length,
        };
        self.cache
            .lock()
            .map_err(|_| app_client::Error::Custom("failed to lock mutex".into()))?
            .insert(slab_id, slab.clone());
        Ok(Some(slab))
    }
}

/// A SlabFetcher fetches slabs on-demand from the indexer.
/// It internally caches fetched slabs to avoid redundant
/// network requests.
#[derive(Clone)]
pub struct SlabFetcher {
    cache: Arc<SlabFetchCache>,
    slabs: VecDeque<Slab>,
}

impl SlabFetcher {
    pub fn new(app_client: AppClient, app_key: PrivateKey, slabs: Vec<Slab>) -> Self {
        Self {
            cache: Arc::new(SlabFetchCache {
                cache: Mutex::new(HashMap::new()),
                app_client,
                app_key,
            }),
            slabs: VecDeque::from(slabs),
        }
    }
}

impl SlabIterator for SlabFetcher {
    type Error = app_client::Error;

    async fn next(&mut self) -> Result<Option<Slab>, Self::Error> {
        let slab = self.slabs.pop_front();
        match slab {
            Some(slab_slice) => self.cache.slab(&slab_slice).await,
            None => Ok(None),
        }
    }

    fn max_length(&self) -> usize {
        self.slabs
            .iter()
            .fold(0, |sum, slab| sum + slab.length as usize)
    }
}

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("QUIC error: {0}")]
    Quic(#[from] quic::Error),

    #[error("encoder error: {0}")]
    Encoder(#[from] erasure_coding::Error),

    #[error("not enough shards: {0}/{1}")]
    NotEnoughShards(u8, u8),

    #[error("invalid range: {0}-{1}")]
    OutOfRange(usize, usize),

    #[error("timeout error: {0}")]
    Timeout(#[from] Elapsed),

    #[error("semaphore error: {0}")]
    SemaphoreError(#[from] tokio::sync::AcquireError),

    #[error("join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("api error: {0}")]
    ApiError(#[from] app_client::Error),

    #[error("invalid slab: {0}")]
    InvalidSlab(String),

    #[error("custom error: {0}")]
    Custom(String),
}

pub struct DownloadOptions {
    /// Maximum number of concurrent sector downloads.
    pub max_inflight: usize,
    pub offset: usize,
    pub length: Option<usize>,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            max_inflight: 20,
            offset: 0,
            length: None,
        }
    }
}

pub struct DownloaderInner {
    account_key: PrivateKey,
    host_client: Client,
    app_client: AppClient,
}

impl DownloaderInner {
    // helper to pair a sector with its erasure-coded index.
    // Required because [FuturesUnordered.push] does not
    // preserve ordering and doesn't play nice with closures.
    async fn try_download_sector(
        self: Arc<Self>,
        _permit: OwnedSemaphorePermit,
        host_key: PublicKey,
        root: Hash256,
        offset: usize,
        limit: usize,
        index: usize,
    ) -> Result<(usize, Vec<u8>), DownloadError> {
        let data = self
            .host_client
            .read_sector(host_key, &self.account_key, root, offset, limit)
            .await?;
        Ok((index, data.to_vec()))
    }
}

#[derive(Clone)]
pub struct Downloader {
    inner: Arc<DownloaderInner>,
}

struct SectorDownloadTask {
    sector: Sector,
    index: usize,
}

impl Downloader {
    pub fn new(app_client: AppClient, host_client: Client, account_key: PrivateKey) -> Self {
        Self {
            inner: Arc::new(DownloaderInner {
                account_key,
                host_client,
                app_client,
            }),
        }
    }

    /// Downloads the shards of an erasure-coded slab.
    /// Successful shards will be decrypted using the
    /// encryption_key.
    ///
    /// offset and limit are the byte range to download
    /// from each sector.
    async fn download_slab_shards(
        &self,
        encryption_key: &EncryptionKey,
        sectors: &[Sector],
        min_shards: u8,
        offset: usize,
        limit: usize,
        max_inflight: usize,
    ) -> Result<Vec<Option<Vec<u8>>>, DownloadError> {
        if sectors.len() < min_shards as usize {
            return Err(DownloadError::InvalidSlab(format!(
                "not enough sectors: have {}, need at least {}",
                sectors.len(),
                min_shards
            )));
        }

        let semaphore = Arc::new(Semaphore::new(max_inflight));
        let mut sectors = sectors
            .iter()
            .enumerate()
            .map(|(index, s)| SectorDownloadTask {
                sector: s.clone(),
                index,
            })
            .collect::<Vec<_>>();
        self.inner
            .host_client
            .prioritize_hosts(&mut sectors, |task| &task.sector.host_key);
        let total_shards = sectors.len();
        let mut sectors = VecDeque::from(sectors);
        let mut download_tasks = JoinSet::new();
        for _ in 0..min_shards {
            match sectors.pop_front() {
                Some(task) => {
                    let inner = self.inner.clone();
                    let permit = semaphore.clone().acquire_owned().await?;
                    download_tasks.spawn(inner.try_download_sector(
                        permit,
                        task.sector.host_key,
                        task.sector.root,
                        offset,
                        limit,
                        task.index,
                    ));
                }
                None => panic!("not enough sectors to satisfy min_shards"), // should be unreachable
            };
        }

        let mut successful: u8 = 0;
        let mut shards = vec![None; total_shards];
        loop {
            tokio::select! {
                biased;
                Some(res) = download_tasks.join_next() => {
                    match res {
                        Ok(Ok((index, mut data))) => {
                            let encryption_key = encryption_key.clone();
                            let data = spawn_blocking(move || {
                                encrypt_shard(&encryption_key, index as u8, offset, &mut data);
                                data
                            }).await?;
                            shards[index] = Some(data);
                            successful += 1;
                            if successful >= min_shards {
                               return Ok(shards);
                            }
                        }
                        Ok(Err(e)) => {
                            debug!("sector download failed {:?}", e);
                            let rem = min_shards.saturating_sub(successful);
                            if rem == 0 {
                                return Ok(shards); // sanity check
                            } else if download_tasks.len() <= rem as usize && let Some(task) = sectors.pop_front() {
                                let permit = semaphore.clone().acquire_owned().await?;
                                // only spawn additional download tasks if there are not
                                // enough to satisfy the required number of shards. The
                                // sleep arm will handle slow hosts.
                                let inner = self.inner.clone();
                                download_tasks.spawn(inner.try_download_sector(
                                    permit,
                                    task.sector.host_key,
                                    task.sector.root,
                                    offset,
                                    limit,
                                    task.index,
                                ));
                            } else if download_tasks.is_empty() && successful < min_shards {
                                return Err(DownloadError::NotEnoughShards(successful, min_shards));
                            }
                        }
                        Err(e) => {
                            debug!("sector download failed {:?}", e);
                            let rem = min_shards.saturating_sub(successful);
                            if rem == 0 {
                                return Ok(shards); // sanity check
                            } else if download_tasks.len() <= rem as usize && let Some(task) = sectors.pop_front() {
                                let permit = semaphore.clone().acquire_owned().await?;
                                // only spawn additional download tasks if there are not
                                // enough to satisfy the required number of shards. The
                                // sleep arm will handle slow hosts.
                                let inner = self.inner.clone();
                                download_tasks.spawn(inner.try_download_sector(
                                    permit,
                                    task.sector.host_key,
                                    task.sector.root,
                                    offset,
                                    limit,
                                    task.index,
                                ));
                            } else if download_tasks.is_empty() && successful < min_shards {
                                return Err(DownloadError::NotEnoughShards(successful, min_shards));
                            }
                        }
                    }
                },
                _ = sleep(Duration::from_secs(1)) => {
                    if let Ok(racer_permit) = semaphore.clone().try_acquire_owned()
                        && let Some(task) = sectors.pop_front() {
                            let inner = self.inner.clone();
                            download_tasks.spawn(inner.try_download_sector(
                                racer_permit,
                                task.sector.host_key,
                                task.sector.root,
                                offset,
                                limit,
                                task.index,
                            ));
                        }
                }
            }
        }
    }

    /// Downloads slabs from the provided SlabIterator and writes
    /// the encrypted data to the provided writer.
    ///
    /// This is a low-level function that can be used to download
    /// arbitrary slabs. Most users should use [Downloader::download]
    /// or [Downloader::download_shared] instead.
    async fn download_slabs<W: AsyncWriteExt + Unpin, S: SlabIterator>(
        &self,
        w: &mut W,
        mut slabs: S,
        options: DownloadOptions,
    ) -> Result<(), DownloadError> {
        if self.inner.host_client.available_hosts() == 0 {
            let hosts = self
                .inner
                .app_client
                .hosts(&self.inner.account_key, HostQuery::default())
                .await?;
            self.inner.host_client.update_hosts(hosts);
        }

        let max_length = slabs.max_length();
        let mut offset = options.offset;
        let mut length = options.length.unwrap_or(max_length);
        if offset > max_length || length == 0 {
            return Ok(());
        }
        loop {
            if length == 0 {
                break;
            }
            let slab = match slabs
                .next()
                .await
                .map_err(|e| DownloadError::Custom(format!("{:?}", e)))?
            {
                Some(s) => s,
                None => break,
            };

            let slab_length = slab.length as usize;
            if offset >= slab_length {
                offset -= slab_length;
                continue;
            }

            // adjust slab range based on offset and length
            let slab_offset = slab.offset as usize + offset;
            let slab_length = (slab_length - offset).min(length);
            offset = 0;

            // compute the sector aligned region to download
            let chunk_size = SEGMENT_SIZE * slab.min_shards as usize;
            let start = (slab_offset / chunk_size) * SEGMENT_SIZE;
            let end = (slab_offset + slab_length).div_ceil(chunk_size) * SEGMENT_SIZE;
            let shard_offset = start;
            let shard_length = end - start;

            let mut shards = self
                .download_slab_shards(
                    &slab.encryption_key,
                    &slab.sectors,
                    slab.min_shards,
                    shard_offset,
                    shard_length,
                    options.max_inflight,
                )
                .await?;
            let data_shards = slab.min_shards as usize;
            let parity_shards = slab.sectors.len() - slab.min_shards as usize;
            let shards = spawn_blocking(move || -> Result<Vec<Option<Vec<u8>>>, DownloadError> {
                let rs = ErasureCoder::new(data_shards, parity_shards)?;
                rs.reconstruct_data_shards(&mut shards)?;
                Ok(shards)
            })
            .await??;
            ErasureCoder::write_data_shards(
                w,
                &shards[..data_shards],
                slab_offset % (SEGMENT_SIZE * slab.min_shards as usize),
                slab_length,
            )
            .await?;
            length -= slab_length;
        }
        w.flush().await?;
        Ok(())
    }

    pub async fn download<W: AsyncWriteExt + Unpin>(
        &self,
        w: W,
        object: &Object,
        options: DownloadOptions,
    ) -> Result<(), DownloadError> {
        let slab_iterator = SlabFetcher::new(
            self.inner.app_client.clone(),
            self.inner.account_key.clone(),
            object.slabs.clone(),
        );
        let mut w = object.writer(w, options.offset);
        self.download_slabs(&mut w, slab_iterator, options).await
    }

    pub async fn download_shared<W: AsyncWriteExt + Unpin>(
        &self,
        w: W,
        object: &SharedObject,
        options: DownloadOptions,
    ) -> Result<(), DownloadError> {
        let slabs: Vec<Slab> = object.slabs().clone();
        let mut w = object.writer(w, options.offset);
        self.download_slabs(&mut w, VecDeque::from(slabs), options)
            .await
    }
}
