use std::collections::VecDeque;
use std::fmt::Debug;
use std::sync::Arc;
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
use crate::{HostClient, Object, Sector, SharedObject, Slab};

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Client error: {0}")]
    Client(String),

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

pub struct DownloaderInner<C: HostClient> {
    account_key: PrivateKey,
    host_client: C,
    app_client: AppClient,
}

impl<C: HostClient> DownloaderInner<C>
where
    DownloadError: From<C::Error>,
{
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
pub struct Downloader<C: HostClient> {
    inner: Arc<DownloaderInner<C>>,
}

struct SectorDownloadTask {
    sector: Sector,
    index: usize,
}

impl<C: HostClient> Downloader<C>
where
    DownloadError: From<C::Error>,
{
    pub fn new(app_client: AppClient, host_client: C, account_key: PrivateKey) -> Self {
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
            .hosts()
            .prioritize(&mut sectors, |task| &task.sector.host_key);
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
                    match res? { // safe because tasks are never cancelled
                        Ok((index, mut data)) => {
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
                        Err(e) => {
                            debug!("sector download failed {:?}", e);
                            let rem = min_shards.saturating_sub(successful);
                            if rem == 0 {
                                return Ok(shards); // sanity check
                            } else if download_tasks.len() + sectors.len() < rem as usize {
                                return Err(DownloadError::NotEnoughShards(successful, min_shards));
                            } else if download_tasks.len() <= rem as usize && let Some(task) = sectors.pop_front() {
                                let permit = semaphore.clone().acquire_owned().await?;
                                // only spawn additional download tasks if there
                                // are not enough to satisfy the required number
                                // of shards. The sleep arm will handle slow
                                // hosts.
                                let inner = self.inner.clone();
                                download_tasks.spawn(inner.try_download_sector(
                                    permit,
                                    task.sector.host_key,
                                    task.sector.root,
                                    offset,
                                    limit,
                                    task.index,
                                ));
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

    /// Downloads the provided slabs and writes the encrypted data to the
    /// provided writer.
    ///
    /// This is a low-level function that can be used to download
    /// arbitrary slabs. Most users should use [Downloader::download]
    /// or [Downloader::download_shared] instead.
    async fn download_slabs<W: AsyncWriteExt + Unpin>(
        &self,
        w: &mut W,
        slabs: &[Slab],
        options: DownloadOptions,
    ) -> Result<(), DownloadError> {
        if self.inner.host_client.hosts().available() == 0 {
            let hosts = self
                .inner
                .app_client
                .hosts(&self.inner.account_key, HostQuery::default())
                .await?;
            self.inner.host_client.hosts().update(hosts);
        }

        let max_length = slabs.iter().map(|s| s.length as usize).sum();
        let mut offset = options.offset;
        let mut length = options.length.unwrap_or(max_length);
        if offset > max_length || length == 0 {
            return Ok(());
        }

        for slab in slabs {
            if length == 0 {
                break;
            }

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
        let mut w = object.writer(w, options.offset);
        self.download_slabs(&mut w, &object.slabs, options).await
    }

    pub async fn download_shared<W: AsyncWriteExt + Unpin>(
        &self,
        w: W,
        object: &SharedObject,
        options: DownloadOptions,
    ) -> Result<(), DownloadError> {
        let mut w = object.writer(w, options.offset);
        self.download_slabs(&mut w, object.slabs(), options).await
    }
}
