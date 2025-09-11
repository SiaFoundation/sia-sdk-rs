use std::sync::Arc;

use bytes::Bytes;
use futures::prelude::*;
use gloo_console::{debug, log};
use gloo_timers::future::TimeoutFuture;
use sia::encryption::{EncryptionKey, encrypt_shards};
use sia::erasure_coding::{self, ErasureCoder};
use sia::rhp;
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use thiserror::Error;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::select;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::app_client::{Client as AppClient, SlabPinParams};
use crate::webtransport::client::{Client, HostQueue};
use crate::webtransport::{self, QueueError};
use crate::{PinnedSlab, Sector, Slab};

#[derive(Debug, Error)]
pub enum UploadError {
    #[error("RHP error: {0}")]
    RPC(#[from] rhp::Error),

    #[error("encoder error: {0}")]
    Encoder(#[from] erasure_coding::Error),
    #[error("not enough shards: {0}/{1}")]
    NotEnoughShards(u8, u8),

    #[error("invalid range: {0}-{1}")]
    OutOfRange(usize, usize),

    #[error("timeout error")]
    Timeout,

    #[error("queue error: {0}")]
    QueueError(#[from] QueueError),

    #[error("semaphore error: {0}")]
    SemaphoreError(#[from] tokio::sync::AcquireError),

    #[error("join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("api error: {0}")]
    ApiError(#[from] crate::app_client::Error),

    #[error("slab id mismatch")]
    InvalidSlabId,

    #[error("webtransport error: {0}")]
    WebTransport(#[from] webtransport::Error),
}

pub struct Uploader {
    app_client: AppClient,
    account_key: PrivateKey,
    max_inflight: usize,

    client: Client,
}

impl Uploader {
    pub fn new(
        app_client: AppClient,
        host_client: Client,
        account_key: PrivateKey,
        max_inflight: usize,
    ) -> Self {
        Uploader {
            app_client,
            account_key,
            max_inflight,
            client: host_client,
        }
    }

    async fn upload_shard(
        _permit: OwnedSemaphorePermit,
        client: Client,
        hosts: HostQueue,
        account_key: PrivateKey,
        data: Bytes,
        write_timeout_ms: u32,
    ) -> Result<Sector, UploadError> {
        let host_key = hosts.pop_front()?;
        let root = select! {
            _ = TimeoutFuture::new(write_timeout_ms) => {
                Err(UploadError::Timeout)
            },
            res = client.write_sector(host_key, &account_key, data) => {
                res.map_err(UploadError::from)
            }
        }?;

        // TODO: retry host upon timeout

        Ok(Sector { root, host_key })
    }

    async fn upload_slab_shard(
        permit: OwnedSemaphorePermit,
        client: Client,
        hosts: HostQueue,
        account_key: PrivateKey,
        data: Bytes,
        shard_index: usize,
    ) -> Result<(usize, Sector), UploadError> {
        const BACKOFF_MULTIPLIER: u32 = 2;

        let semaphore = permit.semaphore().clone();
        let initial_timeout = 10000; // 10 seconds
        let mut tasks = futures::stream::FuturesUnordered::new();
        tasks.push(Self::upload_shard(
            permit,
            client.clone(),
            hosts.clone(),
            account_key.clone(),
            data.clone(),
            initial_timeout,
        ));
        let mut attempts = 0;
        loop {
            let timeout = initial_timeout * BACKOFF_MULTIPLIER.pow(attempts);
            tokio::select! {
                Some(res) = tasks.next() => {
                    match res {
                        Ok(sector) => {
                            debug!(format!("shard {shard_index} upload succeeded"));
                            return Ok((shard_index, sector));
                        }
                        Err(e) => {
                            debug!(format!("shard {shard_index} upload failed {e:?}"));
                            if let UploadError::QueueError(QueueError::NoMoreHosts) = e {
                                log!(format!("all hosts exhausted for shard {shard_index}"));
                                return Err(e);
                            }
                            if tasks.is_empty() {
                                let permit = semaphore.clone().acquire_owned().await?;
                                tasks.push(Self::upload_shard(permit, client.clone(), hosts.clone(), account_key.clone(), data.clone(), timeout));
                            }
                        }
                    }
                },
                _ = TimeoutFuture::new(timeout / 2) => {
                    let permit = semaphore.clone().acquire_owned().await?;
                    debug!(format!("racing slow host for shard {shard_index}"));
                    tasks.push(Self::upload_shard(permit, client.clone(), hosts.clone(), account_key.clone(), data.clone(), timeout));
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
        encryption_key: EncryptionKey,
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Vec<PinnedSlab>, UploadError> {
        let (slab_tx, mut slab_rx) = mpsc::unbounded_channel();
        let semaphore = Arc::new(Semaphore::new(10000)); // TODO: figure out whether to remove this or not
        let host_client = self.client.clone();
        let account_key = self.account_key.clone();
        let read_slab_res = async move {
            // use a buffered reader since the erasure coder reads 64 bytes at a time.
            let mut r = BufReader::new(&mut r);
            let mut slab_index: usize = 0;
            let mut slab_upload_tasks = futures::stream::FuturesUnordered::new();
            loop {
                let rs = ErasureCoder::new(data_shards as usize, parity_shards as usize).unwrap();
                let (mut shards, length) = rs.read_shards(&mut r).await?;
                if length == 0 {
                    break;
                }

                let mut shard_upload_tasks = futures::stream::FuturesUnordered::new();
                // encrypt and start uploading data_shards immediately
                let mut unencrypted_data_shards = shards[..data_shards as usize].to_vec();
                let encrypted_data_shards = {
                    encrypt_shards(&encryption_key, 0, 0, &mut unencrypted_data_shards);
                    unencrypted_data_shards
                };

                let hosts = HostQueue::new(host_client.hosts());
                for (shard_index, shard) in encrypted_data_shards.into_iter().enumerate() {
                    let permit = semaphore.clone().acquire_owned().await?;
                    shard_upload_tasks.push(Self::upload_slab_shard(
                        permit,
                        host_client.clone(),
                        hosts.clone(),
                        account_key.clone(),
                        shard.into(),
                        shard_index,
                    ));
                }

                // calculate the parity shards, encrypt, then upload them
                let encrypted_parity_shards = {
                    rs.encode_shards(&mut shards).unwrap();
                    let mut parity_shards = shards[data_shards as usize..].to_vec();
                    encrypt_shards(&encryption_key, data_shards, 0, &mut parity_shards);
                    parity_shards
                };

                for (shard_index, shard) in encrypted_parity_shards.into_iter().enumerate() {
                    let permit = semaphore.clone().acquire_owned().await?;
                    let shard_index = shard_index + data_shards as usize; // offset by data shards
                    shard_upload_tasks.push(Self::upload_slab_shard(
                        permit,
                        host_client.clone(),
                        hosts.clone(),
                        account_key.clone(),
                        shard.into(),
                        shard_index,
                    ));
                }

                // wait for all shards to finish uploading
                // this is done in a separate task to allow preparing the next slab
                let slab_tx = slab_tx.clone();
                slab_upload_tasks.push({
                    let encryption_key = encryption_key.clone();
                    async move {
                    let mut slab = Slab {
                        sectors: vec![
                            Sector {
                                root: Hash256::default(),
                                host_key: PublicKey::new([0u8; 32])
                            };
                            (data_shards + parity_shards) as usize
                        ],
                        encryption_key,
                        offset: 0,
                        length,
                        min_shards: data_shards,
                    };
                    let mut remaining_shards = data_shards + parity_shards;
                    while let Some(res) = shard_upload_tasks.next().await {
                        let (shard_index, sector) = match res {
                            Ok(s) => s,
                            Err(e) => {
                                slab_tx.send(Err(e)).unwrap();
                                return;
                            }
                        };
                        slab.sectors[shard_index] = sector;
                        remaining_shards -= 1;
                        debug!(format!("slab {slab_index} shard {shard_index} uploaded (remaining: {remaining_shards}"));
                    }
                    // send the completed slab to the channel
                    slab_tx.send(Ok((slab_index, slab))).unwrap();
                }});
                slab_index += 1;
            }
            while (slab_upload_tasks.next().await).is_some() {}
            drop(slab_tx);
            Ok::<(), UploadError>(())
        };

        tokio::pin!(read_slab_res);
        let mut slabs = Vec::new();
        loop {
            select! {
                res = &mut read_slab_res => {
                    res?;
                    return Ok(slabs);
                },
                Some(res) = slab_rx.recv() => {
                    let (slab_index, slab) = res?;
                    debug!(format!("uploaded slab {slab_index}"));
                    // ensure the slabs vector is large enough
                    slabs.resize(
                        slabs.len().max(slab_index + 1),
                        PinnedSlab {
                            id: Hash256::default(),
                            encryption_key: [0u8; 32].into(),
                            min_shards: 0,
                            offset: 0,
                            length: 0,
                        },
                    );
                    let expected_slab_id = slab.digest();
                    let slab_id = self
                        .app_client
                        .pin_slab(SlabPinParams {
                            encryption_key: slab.encryption_key.clone(),
                            min_shards: slab.min_shards,
                            sectors: slab.sectors,
                        })
                        .await?;
                    if slab_id != expected_slab_id {
                        return Err(UploadError::InvalidSlabId);
                    }
                    // overwrite the slab at the index
                    slabs[slab_index] = PinnedSlab {
                        id: slab_id,
                        encryption_key: slab.encryption_key,
                        min_shards: slab.min_shards,
                        offset: slab.offset,
                        length: slab.length,
                    };
                },
            }
        }
    }
}
