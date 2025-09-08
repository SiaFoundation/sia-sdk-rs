use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use log::debug;
use sia::encryption::encrypt_shard;
use sia::erasure_coding::{self, ErasureCoder};
use sia::rhp::SEGMENT_SIZE;
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use thiserror::Error;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::Semaphore;
use tokio::task::{JoinSet, spawn_blocking};
use tokio::time::error::Elapsed;
use tokio::time::sleep;

use crate::app_client::{self, Client as AppClient};
use crate::quic::client::Client;
use crate::quic::{self};
use crate::{PinnedSlab, Sector};

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
}

pub struct DownloaderInner {
    account_key: PrivateKey,
    host_client: Client,
    app_client: AppClient,
    max_inflight: usize,
}

impl DownloaderInner {
    // helper to pair a sector with its erasure-coded index.
    // Required because [FuturesUnordered.push] does not
    // preserve ordering and doesn't play nice with closures.
    async fn try_download_sector(
        self: Arc<Self>,
        semaphore: Arc<Semaphore>,
        host_key: PublicKey,
        root: Hash256,
        offset: usize,
        limit: usize,
        index: usize,
    ) -> Result<(usize, Vec<u8>), DownloadError> {
        let _permit = semaphore.acquire().await?;
        let data = self
            .host_client
            .read_sector(host_key, &self.account_key, root, offset, limit)
            .await?;
        Ok((index, data.to_vec()))
    }
}

pub struct Downloader {
    inner: Arc<DownloaderInner>,
}

impl Downloader {
    pub fn new(
        app_client: AppClient,
        host_client: Client,
        account_key: PrivateKey,
        max_inflight: usize,
    ) -> Self {
        Self {
            inner: Arc::new(DownloaderInner {
                account_key,
                host_client,
                app_client,
                max_inflight,
            }),
        }
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
    ) -> Result<Vec<Option<Vec<u8>>>, DownloadError> {
        let semaphore = Arc::new(Semaphore::new(self.inner.max_inflight));
        let (data_shards, parity_shards) = sectors.split_at(min_shards as usize);

        let mut download_tasks = JoinSet::new();
        for (i, sector) in data_shards.iter().enumerate() {
            let inner = self.inner.clone();
            download_tasks.spawn(inner.try_download_sector(
                semaphore.clone(),
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
                biased;
                Some(res) = download_tasks.join_next() => {
                    match res {
                        Ok(Ok((index, mut data))) => {
                            let encryption_key = *encryption_key;
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
                            } else if download_tasks.len() <= rem as usize && let Some((i, sector)) = parity_shards.pop_front() {
                                // only spawn additional download tasks if there are not
                                // enough to satisfy the required number of shards. The
                                // sleep arm will handle slow hosts.
                                let inner = self.inner.clone();
                                download_tasks.spawn(inner.try_download_sector(
                                    semaphore.clone(),
                                    sector.host_key,
                                    sector.root,
                                    offset,
                                    limit,
                                    i,
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
                            } else if download_tasks.len() <= rem as usize && let Some((i, sector)) = parity_shards.pop_front() {
                                // only spawn additional download tasks if there are not
                                // enough to satisfy the required number of shards. The
                                // sleep arm will handle slow hosts.
                                let inner = self.inner.clone();
                                download_tasks.spawn(inner.try_download_sector(
                                    semaphore.clone(),
                                    sector.host_key,
                                    sector.root,
                                    offset,
                                    limit,
                                    i,
                                ));
                            } else if download_tasks.is_empty() && successful < min_shards {
                                return Err(DownloadError::NotEnoughShards(successful, min_shards));
                            }
                        }
                    }
                },
                _ = sleep(Duration::from_secs(4)) => {
                    if let Some((i, sector)) = parity_shards.pop_front(){
                        let inner = self.inner.clone();
                        download_tasks.spawn(inner.try_download_sector(
                            semaphore.clone(),
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
        slabs: &[PinnedSlab],
        mut offset: usize,
        mut length: usize,
    ) -> Result<(), DownloadError> {
        let max_length = slabs.iter().fold(0, |sum, slab| sum + slab.length);
        if offset + length > max_length {
            return Err(DownloadError::OutOfRange(offset, length));
        } else if length == 0 {
            return Ok(());
        }
        let mut w = BufWriter::new(w);
        for pinned_slab in slabs {
            if length == 0 {
                break;
            }
            let n = pinned_slab.length - pinned_slab.offset;
            if offset >= n {
                offset -= n;
                continue;
            }

            let slab_offset = pinned_slab.offset + offset;
            offset = 0;
            let slab_length = (pinned_slab.length - slab_offset).min(length);
            let (shard_offset, shard_length) =
                Self::sector_region(pinned_slab.min_shards as usize, slab_offset, slab_length);

            let slab = self.inner.app_client.slab(&pinned_slab.id).await?;
            let mut shards = self
                .download_slab_shards(
                    &slab.encryption_key,
                    &slab.sectors,
                    slab.min_shards,
                    shard_offset,
                    shard_length,
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
                &mut w,
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

    /// downloads data from the provided slabs and writes it
    /// to the writer.
    pub async fn download<W: AsyncWriteExt + Unpin>(
        &self,
        w: &mut W,
        slabs: &[PinnedSlab],
    ) -> Result<(), DownloadError> {
        let total_length = slabs.iter().fold(0, |sum, slab| sum + slab.length);
        self.download_range(w, slabs, 0, total_length).await
    }
}
