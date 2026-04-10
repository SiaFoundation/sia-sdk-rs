use std::io;
use std::sync::Arc;

use crate::AppKey;
use bytes::{Bytes, BytesMut};
use log::debug;
use sia_core::rhp4::{self as rhp, SECTOR_SIZE};
use sia_core::signing::PublicKey;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWriteExt, BufReader, SimplexStream, WriteHalf, copy, simplex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use crate::encryption::{EncryptionKey, encrypt_shard};
use crate::erasure_coding::{self, ErasureCoder};
use crate::hosts::{HostQueue, QueueError, RPCError};
use crate::rhp4::Transport;
use crate::task::{AbortOnDropHandle, TaskError, TaskSet};
use crate::time::{Duration, Elapsed, Instant, sleep};
use crate::{Hosts, Object, Sector, Slab};

struct ShardUpload<T: Transport> {
    client: Hosts<T>,
    hosts: HostQueue,
    account_key: Arc<AppKey>,
    data: Bytes,
    slab_index: usize,
    shard_index: usize,
}

impl<T: Transport> ShardUpload<T> {
    fn spawn_write(
        &self,
        tasks: &mut TaskSet<Result<Sector, UploadError>>,
        host_key: PublicKey,
        write_timeout: Duration,
        permit: OwnedSemaphorePermit,
    ) {
        let client = self.client.clone();
        let hosts = self.hosts.clone();
        let account_key = self.account_key.clone();
        let data = self.data.clone();
        let slab_index = self.slab_index;
        let shard_index = self.shard_index;
        task_set_spawn!(tasks, async move {
            let _permit = permit;
            let now = Instant::now();
            let root = client.write_sector(host_key, &account_key.0, data, write_timeout).await
            .inspect_err(|e| {
                debug!(
                    "slab {slab_index} shard {shard_index} upload to host {host_key} failed after {:?} {e}",
                    now.elapsed()
                );
                let _ = hosts.retry(host_key);
            })?;
            debug!(
                "slab {slab_index} shard {shard_index} uploaded to {host_key} in {:?}",
                now.elapsed()
            );
            Ok(Sector { root, host_key })
        });
    }
}

/// Errors that can occur during an upload.
#[derive(Debug, Error)]
pub enum UploadError {
    /// The upload options are invalid.
    #[error("invalid options {0}")]
    InvalidOptions(String),

    /// An I/O error occurred while reading the data to upload.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// A host RPC error occurred during the upload.
    #[error("rhp4 error: {0}")]
    RPC(#[from] RPCError),

    /// The erasure encoder encountered an error.
    #[error("encoder error: {0}")]
    Encoder(#[from] erasure_coding::Error),

    /// Not enough shards were successfully uploaded.
    #[error("not enough shards: {0}/{1}")]
    NotEnoughShards(u8, u8),

    /// The requested range is out of bounds.
    #[error("invalid range: {0}-{1}")]
    OutOfRange(usize, usize),

    /// A host RPC timed out.
    #[error("timeout error: {0}")]
    Timeout(#[from] Elapsed),

    /// An error from the host queue.
    #[error("queue error: {0}")]
    QueueError(#[from] QueueError),

    /// An internal semaphore error.
    #[error("semaphore error: {0}")]
    SemaphoreError(#[from] tokio::sync::AcquireError),

    #[error("task error: {0}")]
    TaskError(#[from] TaskError),

    /// An error from the indexer API.
    #[error("api error: {0}")]
    ApiError(#[from] crate::app_client::Error),

    /// The slab ID returned by the indexer does not match the expected value.
    #[error("slab id mismatch")]
    InvalidSlabId,

    /// The upload was cancelled.
    #[error("upload cancelled")]
    Cancelled,
}

/// Options for configuring an upload.
pub struct UploadOptions {
    /// The number of data shards per slab. Defaults to 10.
    pub data_shards: u8,
    /// The number of parity shards per slab. Defaults to 20.
    pub parity_shards: u8,
    /// The maximum number of concurrent shard uploads. Defaults to 15.
    pub max_inflight: usize,

    /// Optional channel to notify when each shard is uploaded.
    /// This can be used to implement progress reporting.
    pub shard_uploaded: Option<mpsc::UnboundedSender<()>>,
}

impl UploadOptions {
    /// Returns the optimal data size per slab in bytes.
    pub fn optimal_data_size(&self) -> u64 {
        SECTOR_SIZE as u64 * self.data_shards as u64
    }

    /// Returns the total slab size including parity shards in bytes.
    pub fn slab_size(&self) -> u64 {
        SECTOR_SIZE as u64 * (self.data_shards as u64 + self.parity_shards as u64)
    }

    /// Validates the upload options and erasure coding parameters to ensure
    /// sufficient durability.
    ///
    /// This checks that the redundancy ratio is between 1.5x and 4x and that
    /// the probability of recovering the original data meets a minimum threshold
    /// of 99.99%.
    pub fn validate(&self) -> Result<(), UploadError> {
        const MIN_REDUNDANCY: f64 = 1.5;
        const MAX_REDUNDANCY: f64 = 4.0;
        const RECOVERY_PROBABILITY: f64 = 0.75;
        const MIN_RECOVERY_PROBABILITY: f64 = 99.99;
        const MAX_TOTAL_SHARDS: u16 = 256;

        if self.max_inflight == 0 {
            return Err(UploadError::InvalidOptions(
                "max_inflight must be greater than 0".into(),
            ));
        }

        let data_shards = self.data_shards as u16;
        let parity_shards = self.parity_shards as u16;
        let total_shards = data_shards + parity_shards;

        if data_shards == 0 {
            return Err(UploadError::InvalidOptions(
                "data shards cannot be zero".into(),
            ));
        } else if parity_shards == 0 {
            return Err(UploadError::InvalidOptions(
                "parity shards cannot be zero".into(),
            ));
        } else if total_shards > MAX_TOTAL_SHARDS {
            return Err(UploadError::InvalidOptions(format!(
                "total shards {total_shards} exceeds maximum of {MAX_TOTAL_SHARDS}"
            )));
        }

        let redundancy = total_shards as f64 / data_shards as f64;
        if redundancy < MIN_REDUNDANCY {
            return Err(UploadError::InvalidOptions(format!(
                "redundancy of {redundancy:.2} is too low"
            )));
        } else if redundancy > MAX_REDUNDANCY {
            return Err(UploadError::InvalidOptions(format!(
                "redundancy of {redundancy:.2} is too high"
            )));
        }

        // Calculate recovery probability using the binomial CDF.
        // P(X >= data_shards) where X ~ Binomial(total_shards, RECOVERY_PROBABILITY)
        let q = 1.0 - RECOVERY_PROBABILITY;
        let mut term = q.powi(total_shards as i32);
        for i in 0..data_shards {
            term *= (total_shards - i) as f64 / (i + 1) as f64 * (RECOVERY_PROBABILITY / q);
        }
        let mut sum = term;
        for i in data_shards..total_shards {
            term *= (total_shards - i) as f64 / (i + 1) as f64 * (RECOVERY_PROBABILITY / q);
            sum += term;
        }
        let prob = sum * 100.0;
        if prob < MIN_RECOVERY_PROBABILITY {
            return Err(UploadError::InvalidOptions(format!(
                "not enough redundancy {data_shards}-of-{total_shards}: recovery probability {:.2}% is below minimum threshold of {MIN_RECOVERY_PROBABILITY:.2}%",
                (prob * 100.0).floor() / 100.0
            )));
        }
        Ok(())
    }
}

impl Default for UploadOptions {
    fn default() -> Self {
        Self {
            data_shards: 10,
            parity_shards: 20,
            max_inflight: 15,
            shard_uploaded: None,
        }
    }
}

struct ObjectUpload {
    start: u64,
    end: u64,
    object: Object,
}

/// A packed upload allows multiple objects to be uploaded together in a single upload. This can be more
/// efficient than uploading each object separately if the size of the object is less than the minimum
/// slab size.
///
/// The caller must call [finalize](Self::finalize) to complete the upload.
pub struct PackedUpload {
    slab_size: u64,
    length: u64,
    writer: WriteHalf<SimplexStream>,
    objects: Vec<ObjectUpload>,
    upload_handle: AbortOnDropHandle<Result<Vec<Slab>, UploadError>>,
}

impl PackedUpload {
    /// Returns the number of bytes remaining until reaching the optimal
    /// packed size. Adding objects larger than this will start a new slab.
    /// To minimize padding, prioritize objects that fit within the
    /// remaining size.
    pub fn remaining(&self) -> u64 {
        if self.length == 0 {
            return self.slab_size;
        }
        (self.slab_size - (self.length % self.slab_size)) % self.slab_size
    }

    /// Returns the cumulative length of all objects currently in the upload.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Returns the optimal size of each slab.
    pub fn slab_size(&self) -> u64 {
        self.slab_size
    }

    /// Returns the number of slabs after the upload is finalized.
    pub fn slabs(&self) -> u64 {
        self.length.div_ceil(self.slab_size)
    }

    /// Cancels the upload.
    pub fn cancel(self) {
        drop(self.upload_handle);
    }

    /// Finalizes the upload and returns the resulting objects. This will wait for all readers
    /// to finish and all slabs to be uploaded before returning. The resulting objects will contain the metadata needed to download the objects.
    ///
    /// The caller must pin the resulting objects to the indexer when ready.
    pub async fn finalize(mut self) -> Result<Vec<Object>, UploadError> {
        let _ = self.writer.shutdown().await; // ignore error
        let uploaded_slabs = self.upload_handle.await??;
        self.objects
            .into_iter()
            .map(|upload| {
                let mut object = upload.object;
                let slabs = object.slabs_mut();
                let slabs_start = upload.start / self.slab_size;
                let slabs_end = upload.end.div_ceil(self.slab_size);
                let n = slabs_end - slabs_start;
                slabs.extend_from_slice(&uploaded_slabs[slabs_start as usize..slabs_end as usize]);

                slabs[0].offset = (upload.start % self.slab_size) as u32;
                if slabs.len() > 1 {
                    // if spanning multiple slabs, adjust first slab's length
                    slabs[0].length = (self.slab_size - slabs[0].offset as u64) as u32;
                }
                let last_slab_index = (n - 1) as usize;
                let last_slab_offset = slabs[last_slab_index].offset as u64;
                slabs[last_slab_index].length =
                    (upload.end - ((slabs_end - 1) * self.slab_size) - last_slab_offset) as u32;

                Ok(object)
            })
            .collect()
    }

    /// Adds a new object to the upload. The data will be read until EOF and packed into
    /// the upload. The resulting object will contain the metadata needed to download the object. The caller
    /// must call [finalize](Self::finalize) to get the resulting objects after all objects have been added.
    pub async fn add<R: AsyncRead + Unpin>(&mut self, r: R) -> io::Result<u64> {
        if self.upload_handle.is_finished() {
            // should only happen if the upload errored; callers can get the error by calling finalize
            return Err(io::Error::other("cannot add object to finalized upload"));
        }
        let object = Object::default();
        let mut r = object.reader(r, 0);
        let object_length = copy(&mut r, &mut self.writer).await?;
        let start = self.length;
        let end = start + object_length;
        self.objects.push(ObjectUpload { start, end, object });
        self.length += object_length;
        Ok(object_length)
    }
}

#[derive(Clone)]
pub(crate) struct Uploader<T: Transport> {
    app_key: Arc<AppKey>,
    hosts: Hosts<T>,
}

impl<T: Transport> Uploader<T> {
    pub fn new(hosts: Hosts<T>, app_key: Arc<AppKey>) -> Self {
        Uploader { app_key, hosts }
    }

    fn upload_timeout(attempts: usize) -> Duration {
        Duration::from_secs((10 + (5 * attempts as u64)).min(120))
    }

    async fn upload_slab_shard(
        shard: ShardUpload<T>,
        permit: OwnedSemaphorePermit,
        progress_tx: Option<mpsc::UnboundedSender<()>>,
        initial_host: (PublicKey, usize),
    ) -> Result<(usize, Sector), UploadError> {
        let (host_key, attempts) = initial_host;
        let write_timeout = Self::upload_timeout(attempts);
        let semaphore = permit.semaphore().clone();
        let mut tasks = TaskSet::new();
        shard.spawn_write(&mut tasks, host_key, write_timeout, permit);
        loop {
            let active = tasks.len();
            tokio::select! {
                biased;
                Some(res) = tasks.join_next() => {
                    match res.unwrap() {
                        Ok(sector) => {
                            if sector.host_key != host_key {
                                debug!("slab {} shard {} penalizing original host {}", shard.slab_index, shard.shard_index, host_key);
                                shard.client.add_failure(host_key)
                            }
                            if let Some(progress_tx) = progress_tx {
                                let _ = progress_tx.send(());
                            }
                            return Ok((shard.shard_index, sector));
                        }
                        Err(_) => {
                            if tasks.is_empty() {
                                let (host_key, attempts) = shard.hosts.pop_front()?;
                                let write_timeout = Self::upload_timeout(attempts);
                                let permit = semaphore.clone().acquire_owned().await?;
                                shard.spawn_write(&mut tasks, host_key, write_timeout, permit);
                            }
                        }
                    }
                },
                _ = sleep(Duration::from_secs(active.max(1) as u64)) => {
                    if let Ok(racer) = semaphore.clone().try_acquire_owned()
                        && let Ok((host_key, attempts)) = shard.hosts.pop_front() {
                            debug!("slab {} shard {} racing slow host", shard.slab_index, shard.shard_index);
                            let write_timeout = Self::upload_timeout(attempts);
                            shard.spawn_write(&mut tasks, host_key, write_timeout, racer);
                        }
                }
            }
        }
    }

    pub(crate) async fn upload_slabs<R: AsyncRead + Unpin + Send + 'static>(
        client: Hosts<T>,
        app_key: Arc<AppKey>,
        r: R,
        options: UploadOptions,
    ) -> Result<Vec<Slab>, UploadError> {
        options.validate()?;
        let data_shards = options.data_shards as usize;
        let parity_shards = options.parity_shards as usize;
        let total_shards = data_shards + parity_shards;

        // fail fast if there aren't enough hosts before doing any encoding
        if client.available_for_upload() < total_shards {
            return Err(QueueError::InsufficientHosts.into());
        }

        // hard cap all shard uploads including races
        let shard_sema = Arc::new(Semaphore::new(options.max_inflight));
        // cap number of "active" slabs to limit memory usage.
        let slab_sema = Arc::new(Semaphore::new(
            options
                .max_inflight
                .div_ceil(total_shards)
                .saturating_add(1),
        ));

        // use a buffered reader since the erasure coder reads 64 bytes at a time.
        let mut r = BufReader::new(r);
        let mut slab_upload_tasks = TaskSet::new();
        let rs = Arc::new(ErasureCoder::new(data_shards, parity_shards).unwrap());
        let mut slab_index: usize = 0;
        loop {
            let mut shards = vec![BytesMut::zeroed(SECTOR_SIZE); total_shards];
            let length =
                ErasureCoder::read_slab_shards(&mut r, options.data_shards as usize, &mut shards)
                    .await?;
            if length == 0 {
                break; // EoF
            }

            let app_key = app_key.clone();
            let client = client.clone();
            let progress_tx = options.shard_uploaded.clone();
            let rs = rs.clone();
            let shard_sema = shard_sema.clone();
            let slab_sema = slab_sema.clone();

            task_set_spawn!(slab_upload_tasks, async move {
                let _slab_guard = slab_sema.acquire_owned().await?;

                // note: it may seem like a good idea to start uploading the data shards
                // while the parity shards are being calculated, but this also forces
                // cloning the rather large shards and ends up being a net performance
                // decrease (~8%).
                //
                // It could probably be resolved by using a pool, but leaving that as a
                // future optimization for now.
                let shards = maybe_spawn_blocking!({
                    rs.encode_shards(&mut shards)?;
                    Ok::<_, erasure_coding::Error>(shards)
                })?;

                // generate a unique encryption key for the slab
                let slab_key: EncryptionKey = rand::random::<[u8; 32]>().into();

                let host_queue = client.upload_queue();
                // reserve one host per shard upfront to guarantee each shard has at least one host
                let reserved_hosts = host_queue.pop_n(shards.len())?;
                let owned_slab_key = Arc::new(slab_key.clone());
                let start_time = Instant::now();
                let mut shard_upload_tasks = TaskSet::new();
                for (shard_index, mut shard) in shards.into_iter().enumerate() {
                    let app_key = app_key.clone();
                    let owned_slab_key = owned_slab_key.clone();
                    let shard_sema = shard_sema.clone();
                    let host_queue = host_queue.clone();
                    let progress_tx = progress_tx.clone();
                    let initial_host = reserved_hosts[shard_index];
                    let client = client.clone();
                    // Acquire the semaphore inside the spawned future so all tasks
                    // are in the TaskSet before any blocking. With FuturesUnordered
                    // (WASM), tasks only run when polled via join_next() — acquiring
                    // outside would deadlock because completed tasks couldn't release
                    // permits while the spawn loop is blocked on acquire.
                    task_set_spawn!(shard_upload_tasks, async move {
                        let permit = shard_sema.acquire_owned().await?;
                        let shard = maybe_spawn_blocking!({
                            encrypt_shard(&owned_slab_key, shard_index as u8, 0, &mut shard);
                            shard
                        });
                        Self::upload_slab_shard(
                            ShardUpload {
                                client,
                                hosts: host_queue,
                                account_key: app_key,
                                data: shard.into(),
                                slab_index,
                                shard_index,
                            },
                            permit,
                            progress_tx,
                            initial_host,
                        )
                        .await
                    });
                }

                let mut slab_sectors = vec![None; data_shards + parity_shards];
                while let Some(res) = shard_upload_tasks.join_next().await {
                    match res {
                        Ok(Ok((shard_index, sector))) => {
                            slab_sectors[shard_index] = Some(sector);
                        }
                        Ok(Err(e)) => {
                            return Err(e);
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    };
                }
                debug!(
                    "slab {slab_index} uploaded in {:?}",
                    Instant::now().duration_since(start_time)
                );
                Ok((
                    slab_index,
                    Slab {
                        sectors: slab_sectors.into_iter().map(|s| s.unwrap()).collect(),
                        encryption_key: slab_key,
                        offset: 0,
                        length: length as u32,
                        min_shards: options.data_shards,
                    },
                ))
            });
            slab_index += 1;
        }

        let num_slabs = slab_upload_tasks.len();
        let mut slabs: Vec<Option<Slab>> = vec![None; num_slabs];
        while let Some(res) = slab_upload_tasks.join_next().await {
            match res {
                Ok(Ok((slab_index, slab))) => {
                    slabs[slab_index] = Some(slab);
                }
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(e.into()),
            };
        }
        let slabs = slabs.into_iter().map(|s| s.unwrap()).collect();
        Ok(slabs)
    }

    /// Reads until EOF and uploads all slabs. The data will be erasure coded,
    /// encrypted, and uploaded.
    ///
    /// Pass [`Object::default()`] for new uploads. To resume a previous upload,
    /// pass the object returned from the earlier call. Appending data changes
    /// an object's ID. It must be re-pinned afterward and any references to
    /// the previous ID must be updated.
    ///
    /// # Arguments
    /// * `object` - The object to upload into. Use `Object::default()` for new uploads.
    /// * `r` - The reader to read the data from. It will be read until EOF.
    /// * `options` - The [UploadOptions] to use for the upload.
    ///
    /// # Returns
    /// The object containing the metadata needed to download. The caller must
    /// pin the object to the indexer after uploading.
    pub async fn upload<R: AsyncRead + Unpin + Send + 'static>(
        &self,
        mut object: Object,
        r: R,
        options: UploadOptions,
    ) -> Result<Object, UploadError> {
        // use a buffered reader since the erasure coder reads 64 bytes at a time.
        let r = object.reader(BufReader::new(r), object.size());
        let new_slabs =
            Self::upload_slabs(self.hosts.clone(), self.app_key.clone(), r, options).await?;
        let slabs = object.slabs_mut();
        slabs.extend(new_slabs.into_iter());
        Ok(object)
    }

    /// Creates a new packed upload. This allows multiple objects to be packed together
    /// for more efficient uploads. The returned `PackedUpload` can be used to add objects to the upload, and then finalized to get the resulting objects.
    ///
    /// # Arguments
    /// * `options` - The [UploadOptions] to use for the upload.
    ///
    /// # Returns
    /// A [PackedUpload] that can be used to add objects and finalize the upload.
    pub fn upload_packed(&self, options: UploadOptions) -> PackedUpload {
        let app_key = self.app_key.clone();
        let (reader, writer) = simplex(1024 * 1024);
        let client = self.hosts.clone();
        PackedUpload {
            slab_size: options.data_shards as u64 * rhp::SECTOR_SIZE as u64,
            length: 0,
            writer,
            objects: Vec::new(),
            upload_handle: AbortOnDropHandle::new(maybe_spawn!(async move {
                let slabs = Self::upload_slabs(client, app_key, reader, options).await?;
                Ok(slabs)
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(data: u8, parity: u8) -> UploadOptions {
        UploadOptions {
            data_shards: data,
            parity_shards: parity,
            ..Default::default()
        }
    }

    #[test]
    fn test_validate_ec_params() {
        let cases: &[(u8, u8, bool)] = &[
            (0, 6, false),   // zero data shards
            (6, 0, false),   // zero parity shards (total < data)
            (1, 2, false),   // 1-of-3: insufficient recovery probability
            (2, 4, false),   // 2-of-6: insufficient recovery probability
            (4, 4, false),   // 4-of-8: insufficient recovery probability
            (1, 9, false),   // 1-of-10: 10x redundancy is too high
            (60, 15, false), // 60-of-75: 1.25x redundancy is too low
            (10, 20, true),  // 10-of-30
            (40, 40, true),  // 40-of-80
            (30, 30, true),  // 30-of-60
        ];

        for &(data, parity, ok) in cases {
            let total = data as u16 + parity as u16;
            let result = opts(data, parity).validate();
            assert_eq!(
                result.is_ok(),
                ok,
                "{data}-of-{total}: expected ok={ok}, got {:?}",
                result.err()
            );
        }
    }
}
