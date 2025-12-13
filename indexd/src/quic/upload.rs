use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use log::debug;
use rand::TryRngCore;
use rand::rngs::OsRng;
use sia::encryption::{EncryptionKey, encrypt_shards};
use sia::erasure_coding::{self, ErasureCoder};
use sia::rhp;
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use thiserror::Error;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::select;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet, spawn_blocking};
use tokio::time::error::Elapsed;
use tokio::time::{Instant, sleep, timeout};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::app_client::{Client as AppClient, HostQuery, SlabPinParams};
use crate::hosts::{HostQueue, QueueError};
use crate::quic::client::Client;
use crate::quic::{self};
use crate::{Object, Sector, Slab};

#[derive(Debug, Error)]
pub enum UploadError {
    #[error("I/O error: {0}")]
    QUIC(#[from] quic::Error),
    #[error("RHP error: {0}")]
    RPC(#[from] rhp::Error),

    #[error("encoder error: {0}")]
    Encoder(#[from] erasure_coding::Error),
    #[error("not enough shards: {0}/{1}")]
    NotEnoughShards(u8, u8),

    #[error("invalid range: {0}-{1}")]
    OutOfRange(usize, usize),

    #[error("timeout error: {0}")]
    Timeout(#[from] Elapsed),

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

    #[error("upload cancelled")]
    Cancelled,
}

#[derive(Clone)]
pub struct Uploader {
    app_client: AppClient,
    app_key: PrivateKey,

    client: Client,
}

pub struct UploadOptions {
    pub data_shards: u8,
    pub parity_shards: u8,
    pub max_inflight: usize,

    /// Optional metadata to attach to the object.
    /// This will be encrypted with the object's master key.
    pub metadata: Option<Vec<u8>>,
    /// Optional channel to notify when each shard is uploaded.
    /// This can be used to implement progress reporting.
    pub shard_uploaded: Option<mpsc::UnboundedSender<()>>,
}

impl Default for UploadOptions {
    fn default() -> Self {
        Self {
            data_shards: 10,
            parity_shards: 20,
            max_inflight: 16,
            metadata: None,
            shard_uploaded: None,
        }
    }
}

impl Uploader {
    pub fn new(app_client: AppClient, host_client: Client, app_key: PrivateKey) -> Self {
        Uploader {
            app_client,
            app_key,
            client: host_client,
        }
    }

    async fn upload_shard(
        client: Client,
        hosts: HostQueue,
        host_key: PublicKey,
        account_key: PrivateKey,
        data: Bytes,
        write_timeout: Duration,
    ) -> Result<Sector, UploadError> {
        let now = Instant::now();
        let root = timeout(
            write_timeout,
            client.write_sector(host_key, &account_key, data),
        )
        .await
        .inspect_err(|e| {
            debug!(
                "upload to host {host_key} timed out after {:?} {e}",
                now.elapsed()
            );
            let _ = hosts.retry(host_key);
        })?
        .inspect_err(|e| {
            debug!(
                "upload to host {host_key} failed after {:?} {e}",
                now.elapsed()
            );
            let _ = hosts.retry(host_key);
        })?;
        Ok(Sector { root, host_key })
    }

    fn upload_timeout(attempts: usize) -> Duration {
        Duration::from_secs((15 + (attempts as u64 * 2)).max(120))
    }

    async fn upload_slab_shard(
        permit: OwnedSemaphorePermit,
        client: Client,
        hosts: HostQueue,
        account_key: PrivateKey,
        data: Bytes,
        shard_index: usize,
    ) -> Result<(usize, Sector), UploadError> {
        let (host_key, attempts) = hosts.pop_front()?;
        let mut write_timeout = Self::upload_timeout(attempts); // mutable so that it can be adjusted on retries
        let mut tasks = JoinSet::new();
        tasks.spawn(Self::upload_shard(
            client.clone(),
            hosts.clone(),
            host_key,
            account_key.clone(),
            data.clone(),
            write_timeout,
        ));
        let semaphore = permit.semaphore();
        loop {
            let active = tasks.len();
            let hosts = hosts.clone();
            tokio::select! {
                biased;
                Some(res) = tasks.join_next() => {
                    match res.unwrap() {
                        Ok(sector) => {
                            return Ok((shard_index, sector));
                        }
                        Err(e) => {
                            debug!("shard {shard_index} upload failed {e:?}");
                            if tasks.is_empty() {
                                let (host_key, attempts) = hosts.pop_front()?;
                                write_timeout = Self::upload_timeout(attempts);
                                tasks.spawn(Self::upload_shard(client.clone(), hosts.clone(), host_key, account_key.clone(), data.clone(), write_timeout));
                            }
                        }
                    }
                },
                _ = sleep(Duration::from_secs(active as u64)) => {
                    if let Ok(racer) = semaphore.clone().try_acquire_owned() {
                        // only race if there's an empty slot
                        let client = client.clone();
                        let data = data.clone();
                        let account_key = account_key.clone();
                        tasks.spawn(async move {
                            let _racer = racer; // hold the permit until the task completes
                            debug!("racing slow host for shard {shard_index}");
                            let (host_key, attempts) = hosts.pop_front()?;
                            let write_timeout = Self::upload_timeout(attempts);
                            Self::upload_shard(client.clone(), hosts.clone(), host_key, account_key, data, write_timeout).await
                        });
                    }
                }
            }
        }
    }

    /// Reads until EOF and uploads all slabs.
    /// The data will be erasure coded, encrypted,
    /// and uploaded using the uploader's parameters.
    ///
    /// # Warnings
    /// * The `encryption_key` must be unique for every upload. Reusing an
    ///   encryption key will compromise the security of the data.
    ///
    /// # Returns
    /// An object representing the uploaded data.
    pub async fn upload<R: AsyncReadExt + Unpin + Send + 'static>(
        &self,
        cancel: CancellationToken,
        r: R,
        options: UploadOptions,
    ) -> Result<Object, UploadError> {
        if self.client.available_hosts() == 0 {
            let hosts = self
                .app_client
                .hosts(&self.app_key, HostQuery::default())
                .await?;
            self.client.update_hosts(hosts);
        }
        let data_shards = options.data_shards as usize;
        let parity_shards = options.parity_shards as usize;
        let (slab_tx, mut slab_rx) = mpsc::unbounded_channel();
        let semaphore = Arc::new(Semaphore::new(options.max_inflight));
        let host_client = self.client.clone();
        let app_key = self.app_key.clone();
        let mut object = Object::default();
        if let Some(metadata) = options.metadata {
            object.metadata = metadata;
        }

        // use a buffered reader since the erasure coder reads 64 bytes at a time.
        let mut r = object.reader(BufReader::new(r), 0);
        let read_slab_res: JoinHandle<Result<(), UploadError>> = tokio::spawn(async move {
            let mut slab_index: usize = 0;
            let slab_upload_tasks = TaskTracker::new();
            loop {
                let rs = ErasureCoder::new(data_shards, parity_shards).unwrap();
                let (mut shards, length) = rs.read_shards(&mut r).await?;
                if length == 0 {
                    break;
                }

                // unique encryption key for the slab
                let mut slab_key = [0u8; 32];
                OsRng.try_fill_bytes(&mut slab_key).unwrap();
                let slab_key = EncryptionKey::from(slab_key);

                // encrypt and start uploading data_shards immediately
                let mut unencrypted_data_shards = shards[..data_shards].to_vec();
                let encrypted_data_shards = spawn_blocking({
                    let slab_key = slab_key.clone();
                    move || {
                        encrypt_shards(&slab_key, 0, 0, &mut unencrypted_data_shards);
                        unencrypted_data_shards
                    }
                })
                .await?;

                let mut shard_upload_tasks = JoinSet::new();
                let hosts = host_client.host_queue();
                for (shard_index, shard) in encrypted_data_shards.into_iter().enumerate() {
                    let permit = semaphore.clone().acquire_owned().await?;
                    shard_upload_tasks.spawn(Self::upload_slab_shard(
                        permit,
                        host_client.clone(),
                        hosts.clone(),
                        app_key.clone(),
                        shard.into(),
                        shard_index,
                    ));
                }

                // calculate the parity shards, encrypt, then upload them
                let encrypted_parity_shards = spawn_blocking({
                    let slab_key = slab_key.clone();
                    move || -> Vec<Vec<u8>> {
                        rs.encode_shards(&mut shards).unwrap();
                        let mut parity_shards = shards[data_shards..].to_vec();
                        encrypt_shards(&slab_key, options.data_shards, 0, &mut parity_shards);
                        parity_shards
                    }
                })
                .await?;

                for (shard_index, shard) in encrypted_parity_shards.into_iter().enumerate() {
                    let permit = semaphore.clone().acquire_owned().await?;
                    let shard_index = shard_index + data_shards; // offset by data shards
                    shard_upload_tasks.spawn(Self::upload_slab_shard(
                        permit,
                        host_client.clone(),
                        hosts.clone(),
                        app_key.clone(),
                        shard.into(),
                        shard_index,
                    ));
                }

                // wait for all shards to finish uploading
                // this is done in a separate task to allow preparing the next slab
                let slab_tx = slab_tx.clone();
                let progress_tx = options.shard_uploaded.clone();
                slab_upload_tasks.spawn(async move {
                        let mut slab = Slab {
                            sectors: vec![
                                Sector {
                                    root: Hash256::default(),
                                    host_key: PublicKey::new([0u8; 32])
                                };
                                data_shards + parity_shards
                            ],
                            encryption_key: slab_key,
                            offset: 0,
                            length,
                            min_shards: options.data_shards,
                        };
                        let mut remaining_shards = data_shards + parity_shards;
                        while let Some(res) = shard_upload_tasks.join_next().await {
                            let (shard_index, sector) = match res {
                                Ok(Ok(s)) => {
                                    if let Some(chan) = &progress_tx {
                                        let _ = chan.send(());
                                    }
                                    s
                                },
                                Ok(Err(e)) => {
                                    slab_tx.send(Err(e)).unwrap();
                                    return;
                                }
                                Err(e) => {
                                    slab_tx.send(Err(e.into())).unwrap();
                                    return;
                                }
                            };
                            slab.sectors[shard_index] = sector;
                            remaining_shards -= 1;
                            debug!("slab {slab_index} shard {shard_index} uploaded ({remaining_shards} remaining)");
                        }
                        // send the completed slab to the channel
                        slab_tx.send(Ok((slab_index, slab))).unwrap();
                    });
                slab_index += 1;
            }
            slab_upload_tasks.close();
            slab_upload_tasks.wait().await;
            drop(slab_tx);
            Ok(())
        });

        let mut slabs = Vec::new();
        loop {
            select! {
                _ = cancel.cancelled() => {
                    read_slab_res.abort();
                    return Err(UploadError::Cancelled);
                },
                res = slab_rx.recv() => match res {
                    Some(Ok((slab_index, slab))) => {
                        debug!("uploaded slab {slab_index}");
                        // ensure the slabs vector is large enough
                        slabs.resize(
                            slabs.len().max(slab_index + 1),
                            Slab {
                                encryption_key: EncryptionKey::from([0u8; 32]),
                                min_shards: 0,
                                sectors: vec![],
                                offset: 0,
                                length: 0,
                            },
                        );
                        let expected_slab_id = slab.digest();
                        let slab_id = self
                            .app_client
                            .pin_slab(&self.app_key, SlabPinParams {
                                encryption_key: slab.encryption_key.clone(),
                                min_shards: slab.min_shards,
                                sectors: slab.sectors.clone(),
                            })
                            .await?;
                        if slab_id != expected_slab_id {
                            return Err(UploadError::InvalidSlabId);
                        }
                        // overwrite the slab at the index
                        slabs[slab_index] = slab;
                    },
                    Some(Err(e)) => return Err(e),
                    None => break, // channel closed
                },
            }
        }
        read_slab_res.await??;

        object.slabs = slabs;
        let sealed = object.seal(&self.app_key);
        self.app_client.save_object(&self.app_key, &sealed).await?;
        Ok(object)
    }
}
