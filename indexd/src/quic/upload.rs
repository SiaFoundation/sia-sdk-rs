use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use log::debug;
use sia::encryption::{CipherReader, EncryptionKey, encrypt_shards};
use sia::erasure_coding::{self, ErasureCoder};
use sia::rhp;
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use thiserror::Error;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet, spawn_blocking};
use tokio::time::error::Elapsed;
use tokio::time::{sleep, timeout};
use tokio_util::task::TaskTracker;

use crate::app_client::{Client as AppClient, SlabPinParams};
use crate::quic::client::{Client, HostQueue};
use crate::quic::{self, QueueError};
use crate::{Object, Sector, Slab, SlabSlice};

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
}

pub struct Uploader {
    app_client: AppClient,
    account_key: PrivateKey,

    client: Client,
}

pub struct UploadOptions {
    pub data_shards: u8,
    pub parity_shards: u8,
    pub max_inflight: usize,
    /// Optional channel to notify when each shard is uploaded.
    /// This can be used to implement progress reporting.
    pub shard_uploaded: Option<mpsc::UnboundedSender<()>>,
}

impl Default for UploadOptions {
    fn default() -> Self {
        Self {
            data_shards: 10,
            parity_shards: 30,
            max_inflight: 16,
            shard_uploaded: None,
        }
    }
}

impl Uploader {
    pub fn new(app_client: AppClient, host_client: Client, account_key: PrivateKey) -> Self {
        Uploader {
            app_client,
            account_key,
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
        let root = timeout(
            write_timeout,
            client.write_sector(host_key, &account_key, data),
        )
        .await
        .inspect_err(|_| {
            let _ = hosts.retry(host_key);
        })?
        .inspect_err(|_| {
            let _ = hosts.retry(host_key);
        })?;
        Ok(Sector { root, host_key })
    }

    async fn upload_slab_shard(
        permit: OwnedSemaphorePermit,
        client: Client,
        hosts: HostQueue,
        account_key: PrivateKey,
        data: Bytes,
        shard_index: usize,
        progress_callback: Option<UnboundedSender<()>>,
    ) -> Result<(usize, Sector), UploadError> {
        let (host_key, attempts) = hosts.pop_front()?;
        let write_timeout = Duration::from_millis(2500 + (attempts as u64 * 1000));
        let mut tasks = JoinSet::new();
        tasks.spawn(Self::upload_shard(
            client.clone(),
            hosts.clone(),
            host_key,
            account_key.clone(),
            data.clone(),
            write_timeout,
        ));
        let mut write_timeout = write_timeout;
        let semaphore = permit.semaphore();
        loop {
            let hosts = hosts.clone();
            tokio::select! {
                biased;
                Some(res) = tasks.join_next() => {
                    match res.unwrap() {
                        Ok(sector) => {
                            if let Some(cb) = &progress_callback {
                                let _ = cb.send(());
                            }
                            return Ok((shard_index, sector));
                        }
                        Err(e) => {
                            debug!("shard {shard_index} upload failed {e:?}");
                            if tasks.is_empty() {
                                let (host_key, attempts) = hosts.pop_front()?;
                                write_timeout = Duration::from_millis(2500 + attempts as u64 * 1000);
                                tasks.spawn(Self::upload_shard(client.clone(),hosts.clone(), host_key, account_key.clone(), data.clone(), write_timeout));
                            }
                        }
                    }
                },
                _ = sleep(write_timeout/2) => {
                    if let Ok(racer) = semaphore.clone().try_acquire_owned() {
                        // only race if there's an empty slot
                        let client = client.clone();
                        let data = data.clone();
                        let account_key = account_key.clone();
                        tasks.spawn(async move {
                            let _racer = racer; // hold the permit until the task completes
                            debug!("racing slow host for shard {shard_index}");
                            let (host_key, attempts) = hosts.pop_front()?;
                            let write_timeout = Duration::from_millis(500 + attempts as u64 * 10);
                            Self::upload_shard(client.clone(),hosts.clone(), host_key, account_key, data, write_timeout).await
                        });
                    }
                }
            }
        }
    }

    /// Reads until EOF and uploads all slabs.
    /// The data will be erasure coded, encrypted,
    /// and uploaded using the uploader's parameters.
    pub async fn upload<R: AsyncReadExt + Unpin + Send + 'static>(
        &self,
        mut r: R,
        encryption_key: EncryptionKey,
        meta: Option<Vec<u8>>,
        options: UploadOptions,
    ) -> Result<Object, UploadError> {
        if self.client.hosts().is_empty() {
            let hosts = self.app_client.hosts().await?;
            self.client.update_hosts(hosts);
        }
        let data_shards = options.data_shards as usize;
        let parity_shards = options.parity_shards as usize;
        let (slab_tx, mut slab_rx) = mpsc::unbounded_channel();
        let semaphore = Arc::new(Semaphore::new(options.max_inflight));
        let host_client = self.client.clone();
        let account_key = self.account_key.clone();
        let read_slab_res: JoinHandle<Result<(), UploadError>> = tokio::spawn(async move {
            // use a buffered reader since the erasure coder reads 64 bytes at a time.
            let r = BufReader::new(&mut r);

            // encrypt the stream
            let mut r = CipherReader::new(r, encryption_key, 0);

            let mut slab_index: usize = 0;
            let slab_upload_tasks = TaskTracker::new();
            loop {
                let rs = ErasureCoder::new(data_shards, parity_shards).unwrap();
                let (mut shards, length) = rs.read_shards(&mut r).await?;
                if length == 0 {
                    break;
                }

                // unique encryption key for the slab
                let slab_key = EncryptionKey::from(rand::random::<[u8; 32]>());

                let mut shard_upload_tasks = JoinSet::new();
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

                let hosts = HostQueue::new(host_client.hosts());
                for (shard_index, shard) in encrypted_data_shards.into_iter().enumerate() {
                    let permit = semaphore.clone().acquire_owned().await?;
                    shard_upload_tasks.spawn(Self::upload_slab_shard(
                        permit,
                        host_client.clone(),
                        hosts.clone(),
                        account_key.clone(),
                        shard.into(),
                        shard_index,
                        options.shard_uploaded.clone(),
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
                        account_key.clone(),
                        shard.into(),
                        shard_index,
                        options.shard_uploaded.clone(),
                    ));
                }

                // wait for all shards to finish uploading
                // this is done in a separate task to allow preparing the next slab
                let slab_tx = slab_tx.clone();
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
                            Ok(Ok(s)) => s,
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
        while let Some(res) = slab_rx.recv().await {
            let (slab_index, slab) = res?;
            debug!("uploaded slab {slab_index}");
            // ensure the slabs vector is large enough
            slabs.resize(
                slabs.len().max(slab_index + 1),
                SlabSlice {
                    slab_id: Hash256::default(),
                    offset: 0,
                    length: 0,
                },
            );
            let expected_slab_id = slab.digest();
            let slab_id = self
                .app_client
                .pin_slab(SlabPinParams {
                    encryption_key: slab.encryption_key,
                    min_shards: slab.min_shards,
                    sectors: slab.sectors,
                })
                .await?;
            if slab_id != expected_slab_id {
                return Err(UploadError::InvalidSlabId);
            }
            // overwrite the slab at the index
            slabs[slab_index] = SlabSlice {
                slab_id,
                offset: slab.offset,
                length: slab.length,
            };
        }
        read_slab_res.await??;

        let object = Object::new(slabs, meta);
        self.app_client.save_object(&object).await?;
        Ok(object)
    }
}
