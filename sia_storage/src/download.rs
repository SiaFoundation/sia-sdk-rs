use std::collections::VecDeque;
use std::fmt::Debug;
use std::sync::Arc;

use bytes::BytesMut;
use log::debug;
use sia_core::rhp4::SEGMENT_SIZE;
use sia_core::signing::PrivateKey;
use thiserror::Error;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::encryption::{EncryptionKey, encrypt_shard};
use crate::erasure_coding::{self, ErasureCoder};
use crate::hosts::RPCError;
use crate::time::{Duration, Elapsed, Instant, sleep};
use crate::{Hosts, Object, Sector};

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

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

    #[error("invalid slab: {0}")]
    InvalidSlab(String),

    #[error("rhp4 error: {0}")]
    RPC(#[from] RPCError),

    #[error("custom error: {0}")]
    Custom(String),
}

pub struct DownloadOptions {
    /// Maximum number of concurrent sector downloads.
    pub max_inflight: usize,
    pub offset: u64,
    pub length: Option<u64>,
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

struct SectorDownloadTask {
    sector: Sector,
    offset: u64,
    length: u64,
    shard_index: usize,
}

struct SlabDownload {
    client: Hosts,
    account_key: Arc<PrivateKey>,
    encryption_key: Arc<EncryptionKey>,
    semaphore: Arc<Semaphore>,
    slab_index: usize,
    min_shards: u8,
    offset: usize,
}

impl SlabDownload {
    fn spawn_read(
        &self,
        tasks: &mut JoinSet<Result<(usize, BytesMut), DownloadError>>,
        task: SectorDownloadTask,
        permit: OwnedSemaphorePermit,
    ) {
        let client = self.client.clone();
        let account_key = self.account_key.clone();
        let encryption_key = self.encryption_key.clone();
        let slab_index = self.slab_index;
        let offset = self.offset;
        join_set_spawn!(tasks, async move {
            let _permit = permit;
            let shard_index = task.shard_index;
            let start = Instant::now();
            let data = client
                .read_sector(
                    task.sector.host_key,
                    &account_key,
                    task.sector.root,
                    task.offset as usize,
                    task.length as usize,
                    Duration::from_secs(10),
                )
                .await
                .inspect_err(|_| {
                    debug!(
                        "download slab {slab_index} shard {shard_index} from host {} failed in {:?}",
                        task.sector.host_key,
                        start.elapsed()
                    )
                })?;
            debug!(
                "download slab {slab_index} shard {shard_index} from host {} in {:?}",
                task.sector.host_key,
                start.elapsed()
            );
            let mut data = data.try_into_mut().unwrap(); // no other references to the data exist, so this is safe
            let data = maybe_spawn_blocking!({
                encrypt_shard(&encryption_key, shard_index as u8, offset, &mut data);
                data
            });
            Ok((shard_index, data))
        });
    }

    async fn recover_shards(
        &self,
        sectors: &[Sector],
        offset: u64,
        length: u64,
    ) -> Result<Vec<Option<BytesMut>>, DownloadError> {
        if sectors.len() < self.min_shards as usize {
            return Err(DownloadError::InvalidSlab(format!(
                "not enough sectors: have {}, need at least {}",
                sectors.len(),
                self.min_shards
            )));
        }
        let start = Instant::now();
        let mut sectors = sectors
            .iter()
            .enumerate()
            .map(|(shard_index, s)| SectorDownloadTask {
                sector: s.clone(),
                offset,
                length,
                shard_index,
            })
            .collect::<Vec<_>>();
        self.client
            .prioritize(&mut sectors, |task| &task.sector.host_key);
        let total_shards = sectors.len();
        let mut sectors = VecDeque::from(sectors);
        let mut tasks = JoinSet::new();

        for _ in 0..self.min_shards {
            let task = sectors
                .pop_front()
                .expect("not enough sectors to satisfy min_shards");
            let permit = self.semaphore.clone().acquire_owned().await?;
            self.spawn_read(&mut tasks, task, permit);
        }

        let mut successful: u8 = 0;
        let mut shards = vec![None; total_shards];
        loop {
            tokio::select! {
                biased;
                Some(res) = tasks.join_next() => {
                    match res? { // safe because tasks are never cancelled
                        Ok((index, data)) => {
                            shards[index] = Some(data);
                            successful += 1;
                            if successful >= self.min_shards {
                                debug!("download slab {} successfully recovered {successful}/{total_shards} shards in {:?}", self.slab_index, start.elapsed());
                                return Ok(shards);
                            }
                        }
                        Err(_) => {
                            let rem = self.min_shards.saturating_sub(successful);
                            if rem == 0 {
                                return Ok(shards); // sanity check
                            } else if tasks.len() + sectors.len() < rem as usize {
                                return Err(DownloadError::NotEnoughShards(successful, self.min_shards));
                            } else if tasks.len() <= rem as usize
                                && let Some(task) = sectors.pop_front() {
                                    let permit = self.semaphore.clone().acquire_owned().await?;
                                    // only spawn additional download tasks if there
                                    // are not enough to satisfy the required number
                                    // of shards. The sleep arm will handle slow
                                    // hosts.
                                    self.spawn_read(&mut tasks, task, permit);
                                }
                        }
                    }
                },
                _ = sleep(Duration::from_secs(1)) => {
                    if let Ok(permit) = self.semaphore.clone().try_acquire_owned()
                        && let Some(task) = sectors.pop_front() {
                        self.spawn_read(&mut tasks, task, permit);
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct Downloader {
    account_key: Arc<PrivateKey>,
    hosts: Hosts,
}

impl Downloader {
    pub fn new(hosts: Hosts, account_key: Arc<PrivateKey>) -> Self {
        Self { account_key, hosts }
    }

    /// Downloads the provided slabs and writes the decrypted data to the
    /// provided writer.
    pub async fn download<W: AsyncWrite + Unpin>(
        &self,
        w: &mut W,
        object: &Object,
        options: DownloadOptions,
    ) -> Result<(), DownloadError> {
        let mut w = object.writer(w, options.offset as usize);
        let mut offset = options.offset;
        let max_length = object.size();
        let mut length = options.length.unwrap_or(max_length);
        if offset > max_length || length == 0 {
            return Ok(());
        }

        for (slab_index, slab) in object.slabs().iter().enumerate() {
            if length == 0 {
                break;
            }

            let slab_length = slab.length as u64;
            if offset >= slab_length {
                offset -= slab_length;
                continue;
            }

            // adjust slab range based on offset and length
            let slab_offset = slab.offset as u64 + offset;
            let slab_length = (slab_length - offset).min(length);
            offset = 0;

            // compute the sector aligned region to download
            let chunk_size = SEGMENT_SIZE as u64 * slab.min_shards as u64;
            let start = (slab_offset / chunk_size) * SEGMENT_SIZE as u64;
            let end = (slab_offset + slab_length).div_ceil(chunk_size) * SEGMENT_SIZE as u64;
            let shard_offset = start;
            let shard_length = end - start;

            let data_shards = slab.min_shards as usize;
            let parity_shards = slab.sectors.len() - slab.min_shards as usize;
            let slab_download = SlabDownload {
                min_shards: slab.min_shards,
                client: self.hosts.clone(),
                account_key: self.account_key.clone(),
                encryption_key: Arc::new(slab.encryption_key.clone()),
                semaphore: Arc::new(Semaphore::new(options.max_inflight)),
                slab_index,
                offset: shard_offset as usize,
            };
            let start = Instant::now();
            let mut shards = slab_download
                .recover_shards(&slab.sectors, shard_offset, shard_length)
                .await
                .inspect(|_| {
                    debug!(
                        "download slab {slab_index} successfully recovered shards in {:?}",
                        start.elapsed()
                    )
                })?;

            let encoding_start = Instant::now();
            let shards = maybe_spawn_blocking!({
                let rs = ErasureCoder::new(data_shards, parity_shards)?;
                rs.reconstruct_data_shards(&mut shards)?;
                Ok::<_, DownloadError>(shards)
            })?;
            debug!(
                "reconstructed slab {} in {:?}",
                slab_index,
                encoding_start.elapsed()
            );
            ErasureCoder::write_data_shards(
                &mut w,
                &shards[..data_shards],
                slab_offset as usize % (SEGMENT_SIZE * slab.min_shards as usize),
                slab_length as usize,
            )
            .await?;
            length -= slab_length;
        }
        w.flush().await?;
        Ok(())
    }
}
