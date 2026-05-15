use std::collections::{HashSet, VecDeque};
use std::io;
use std::sync::{Arc, Mutex};

use crate::encryption::{EncryptionKey, encrypt_shard};
use crate::erasure_coding::{self, ErasureCoder, ReadSlab, SlabReader};
use crate::hosts::{QueueError, RPCError};
use crate::rhp4::Client;
use crate::task::AbortOnDropHandle;
use crate::time::{Duration, Elapsed, Instant, sleep};
use crate::{
    AppKey, Hosts, Object, Sector, ShardProgress, ShardProgressCallback, Slab, UploadOptions,
};
use bytes::Bytes;
use log::debug;
use sia_core::rhp4::SECTOR_SIZE;
use sia_core::signing::PublicKey;
use thiserror::Error;
use tokio::io::{AsyncRead, BufReader};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

struct ShardUpload {
    semaphore: Arc<Semaphore>,
    client: Hosts<Client>,
    account_key: Arc<AppKey>,
    data: Bytes,
    slab_index: usize,
    shard_index: usize,
    // Tracks hosts already used by any shard in this slab.
    used_hosts: Arc<Mutex<HashSet<PublicKey>>>,
}

struct SectorUploadResult {
    sector: Sector,
    shard_index: usize,
    elapsed: Duration,
}

const UPLOAD_TIMEOUT: Duration = Duration::from_secs(90);

impl ShardUpload {
    fn spawn_write(
        &self,
        tasks: &mut JoinSet<Result<SectorUploadResult, UploadError>>,
        host_key: PublicKey,
        write_timeout: Duration,
        permit: OwnedSemaphorePermit,
    ) {
        let client = self.client.clone();
        let account_key = self.account_key.clone();
        let data = self.data.clone();
        let slab_index = self.slab_index;
        let shard_index = self.shard_index;
        join_set_spawn!(tasks, async move {
            let _permit = permit;
            let now = Instant::now();
            let root = client.write_sector(host_key, &account_key.0, data, write_timeout).await
                .inspect_err(|e| {
                    debug!(
                        "slab {slab_index} shard {shard_index} upload to host {host_key} failed after {:?} {e}",
                        now.elapsed()
                    );
                })?;
            let elapsed = now.elapsed();
            debug!(
                "slab {slab_index} shard {shard_index} uploaded to {host_key} in {:?}",
                elapsed
            );
            Ok(SectorUploadResult {
                sector: Sector { root, host_key },
                shard_index,
                elapsed,
            })
        });
    }

    /// Atomically pick the next-best host for this shard and reserve it
    /// against the slab's `slab_used` set so no other shard in the slab
    /// picks the same host. Returns `None` only when no eligible host
    /// remains.
    fn pick_next_host(&self) -> Option<PublicKey> {
        let mut used = self.used_hosts.lock().unwrap();
        let next = self.client.next_upload_host(&used)?;
        used.insert(next);
        Some(next)
    }

    async fn upload_shard(self) -> Result<SectorUploadResult, UploadError> {
        let permit = self.semaphore.clone().acquire_owned().await?;
        let initial = self.pick_next_host().ok_or(QueueError::NoMoreHosts)?;
        let mut tasks = JoinSet::new();
        self.spawn_write(&mut tasks, initial, UPLOAD_TIMEOUT, permit);
        loop {
            let active = tasks.len();
            tokio::select! {
                biased;
                Some(res) = tasks.join_next() => {
                    match res? {
                        Ok(result) => {
                            if result.sector.host_key != initial {
                                debug!(
                                    "slab {} shard {} penalizing original host {}",
                                    self.slab_index, self.shard_index, initial
                                );
                                self.client.add_failure(initial)
                            }
                            return Ok(result);
                        }
                        Err(_) => {
                            // write_sector already incremented failure_rate
                            // on its error path, dropping the host's score.
                            // Pick the next best host not already used by
                            // any shard in this slab.
                            if tasks.is_empty() {
                                let next = self.pick_next_host()
                                    .ok_or(QueueError::NoMoreHosts)?;
                                let permit = self.semaphore.clone().acquire_owned().await?;
                                self.spawn_write(&mut tasks, next, UPLOAD_TIMEOUT, permit);
                            }
                        }
                    }
                },
                _ = sleep(Duration::from_secs(active.max(1) as u64)) => {
                    if let Ok(racer) = self.semaphore.clone().try_acquire_owned()
                        && let Some(next) = self.pick_next_host() {
                            debug!(
                                "slab {} shard {} racing slow host with {next}",
                                self.slab_index, self.shard_index
                            );
                            self.spawn_write(&mut tasks, next, UPLOAD_TIMEOUT, racer);
                        }
                }
            }
        }
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

    /// An internal task join error.
    #[error("join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

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

struct UploadedSlab {
    encryption_key: EncryptionKey,
    length: u32,
    shards: Vec<Option<Sector>>,
}

/// A single-use streaming upload pipeline. Feed data into it by calling
/// [read](Upload::read) repeatedly, then complete the upload with
/// [finish](Upload::finish) to recover the uploaded slabs.
pub(crate) struct Upload {
    client: Hosts<Client>,
    app_key: Arc<AppKey>,
    erasure_coder: Arc<ErasureCoder>,
    slab_buffer: Option<SlabReader>,
    /// Semaphore to limit the maximum number of slabs in memory at once.
    slab_sema: Arc<Semaphore>,
    /// Semaphore to limit the maximum number of shards in flight at once.
    /// Separate from `slab_sema` since slabs can be buffered while waiting
    /// for shard uploads to complete, and we want to allow some buffering to
    /// improve performance.
    shard_sema: Arc<Semaphore>,
    slab_tasks: VecDeque<AbortOnDropHandle<Result<UploadedSlab, UploadError>>>,
    shard_uploaded: Option<ShardProgressCallback>,
}

impl Upload {
    pub(crate) fn new(
        client: Hosts<Client>,
        app_key: Arc<AppKey>,
        options: UploadOptions,
    ) -> Result<Self, UploadError> {
        options.validate()?;
        let total_shards = options.data_shards as usize + options.parity_shards as usize;
        if client.available_for_upload() < total_shards {
            return Err(QueueError::InsufficientHosts.into());
        }
        let erasure_coder =
            ErasureCoder::new(options.data_shards as usize, options.parity_shards as usize)
                .map_err(|e| {
                    UploadError::InvalidOptions(format!("failed to create erasure coder: {e}"))
                })?;

        let total_shards = options.data_shards as usize + options.parity_shards as usize;
        // cap number of active slabs to limit memory usage.
        let max_slabs = options
            .max_inflight
            .div_ceil(total_shards)
            .saturating_add(1);
        Ok(Self {
            client,
            app_key,
            slab_buffer: Some(SlabReader::new(
                options.data_shards as usize,
                options.parity_shards as usize,
            )),
            erasure_coder: Arc::new(erasure_coder),
            slab_sema: Arc::new(Semaphore::new(max_slabs)),
            shard_sema: Arc::new(Semaphore::new(options.max_inflight)),
            slab_tasks: VecDeque::new(),
            shard_uploaded: options.shard_uploaded,
        })
    }

    async fn spawn_slab(&mut self, slab: ReadSlab) -> Result<(), UploadError> {
        let client = self.client.clone();
        let rs = self.erasure_coder.clone();
        let shard_sema = self.shard_sema.clone();
        let app_key = self.app_key.clone();
        let progress_callback = self.shard_uploaded.clone();
        let slab_index = self.slab_tasks.len();
        let permit = self.slab_sema.clone().acquire_owned().await?;
        let handle = AbortOnDropHandle::new(maybe_spawn!(async move {
            let _permit = permit;
            let total_shards = slab.shards.len();
            let slab_key: EncryptionKey = rand::random::<[u8; 32]>().into();

            // Encode parity shards on a blocking thread; encryption runs
            // per-shard below so it parallelizes across the blocking pool.
            let mut shards = slab.shards;
            let shards = maybe_spawn_blocking!({
                let start = Instant::now();
                rs.encode_shards(&mut shards)?;
                debug!("slab {} encoded in {:?}", slab_index, start.elapsed());
                Ok::<_, UploadError>(shards)
            })?;

            // No pre-assignment of hosts: each shard picks its host
            // just-in-time via `Hosts::next_upload_host`, which scores by
            // `throughput / (inflight + 1)`. This disperses load across
            // hosts naturally — multiple slabs running in parallel won't
            // all pile onto the same top-N hosts, because by the time
            // slab N+1's shards pick, slab N's chosen hosts have higher
            // inflight and lower score.
            //
            // `used_hosts` enforces that every shard within this slab lands
            // on a distinct host (the indexer rejects duplicate sectors
            // because they break redundancy). Every host any shard picks
            // — initial, retry, or racer — is added to the set.
            let used_hosts: Arc<Mutex<HashSet<PublicKey>>> =
                Arc::new(Mutex::new(HashSet::with_capacity(total_shards)));
            let owned_slab_key = Arc::new(slab_key.clone());
            let mut shard_tasks: JoinSet<Result<SectorUploadResult, UploadError>> = JoinSet::new();
            for (shard_index, mut shard) in shards.into_iter().enumerate() {
                let owned_slab_key = owned_slab_key.clone();
                let shard_client = client.clone();
                let shard_account_key = app_key.clone();
                let shard_sema_inner = shard_sema.clone();
                let used_hosts = used_hosts.clone();
                join_set_spawn!(shard_tasks, async move {
                    let shard = maybe_spawn_blocking!({
                        encrypt_shard(&owned_slab_key, shard_index as u8, 0, &mut shard);
                        shard
                    });
                    let shard_upload = ShardUpload {
                        semaphore: shard_sema_inner,
                        client: shard_client,
                        account_key: shard_account_key,
                        data: Bytes::from(shard),
                        slab_index,
                        shard_index,
                        used_hosts,
                    };
                    shard_upload.upload_shard().await
                });
            }

            let mut slab_out = UploadedSlab {
                encryption_key: slab_key,
                length: slab.length as u32,
                shards: vec![None; total_shards],
            };
            while let Some(res) = shard_tasks.join_next().await {
                let result: SectorUploadResult = res??;
                if let Some(callback) = &progress_callback {
                    callback(ShardProgress {
                        host_key: result.sector.host_key,
                        shard_index: result.shard_index,
                        slab_index,
                        shard_size: SECTOR_SIZE,
                        elapsed: result.elapsed,
                    });
                }
                slab_out.shards[result.shard_index] = Some(result.sector);
            }
            Ok(slab_out)
        }));
        self.slab_tasks.push_back(handle);
        Ok(())
    }

    /// Returns the cumulative number of bytes that have landed in the pipeline
    /// across all [read](Self::read) calls, including bytes from reads that
    /// errored part-way. Callers can diff this across a call to recover a
    /// partial count on error and treat the bytes as dead padding.
    pub(crate) fn length(&self) -> u64 {
        self.slab_buffer
            .as_ref()
            .map(|b| b.total_length())
            .unwrap_or(0)
    }

    /// Reads from the provided reader, buffering data into slabs and spawning
    /// slab-upload tasks as they fill. Returns the number of bytes read.
    pub(crate) async fn read<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<u64, UploadError> {
        // buffer the reader since SlabReader reads 64 bytes at a time
        let mut reader = BufReader::new(reader);
        let mut total_length: u64 = 0;
        loop {
            let (n, slab) = self
                .slab_buffer
                .as_mut()
                .unwrap()
                .read_slab(&mut reader)
                .await?;
            if n == 0 {
                return Ok(total_length);
            }
            total_length += n as u64;

            if let Some(slab) = slab {
                self.spawn_slab(slab).await?;
            }
        }
    }

    /// Finalizes the pipeline, flushing any trailing partial slab and awaiting
    /// all in-flight uploads. Returns the uploaded slabs in order.
    pub(crate) async fn finish(mut self) -> Result<Vec<Slab>, UploadError> {
        let last_slab = self.slab_buffer.take().unwrap().finish();
        if let Some(slab) = last_slab {
            self.spawn_slab(slab).await?;
        }
        let min_shards = self.erasure_coder.data_shards() as u8;
        let mut slabs = Vec::with_capacity(self.slab_tasks.len());
        while let Some(handle) = self.slab_tasks.pop_front() {
            let slab = handle.await??;
            slabs.push(Slab {
                encryption_key: slab.encryption_key,
                offset: 0,
                min_shards,
                length: slab.length,
                sectors: slab.shards.into_iter().map(|s| s.unwrap()).collect(),
            });
        }
        Ok(slabs)
    }

    /// Returns the number of bytes remaining until reaching the optimal
    /// packed size. Adding objects larger than this will start a new slab.
    pub(crate) fn remaining(&self) -> usize {
        let slab_buffer = self.slab_buffer.as_ref().unwrap();
        slab_buffer
            .optimal_data_size()
            .saturating_sub(slab_buffer.length())
    }

    /// Returns the optimal size of each slab.
    pub(crate) fn optimal_data_size(&self) -> usize {
        self.slab_buffer.as_ref().unwrap().optimal_data_size()
    }
}

/// Reads from the provided reader until EOF and uploads its contents as a
/// sequence of slabs. Convenience wrapper around [Upload].
pub(crate) async fn upload_slabs<R: AsyncRead + Unpin>(
    hosts: Hosts<Client>,
    app_key: Arc<AppKey>,
    mut reader: R,
    options: UploadOptions,
) -> Result<Vec<Slab>, UploadError> {
    let mut upload = Upload::new(hosts, app_key, options)?;
    upload.read(&mut reader).await?;
    upload.finish().await
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
    upload: Upload,
    objects: Vec<ObjectUpload>,
}

impl PackedUpload {
    pub(crate) fn new(
        client: Hosts<Client>,
        app_key: Arc<AppKey>,
        options: UploadOptions,
    ) -> Result<Self, UploadError> {
        Ok(Self {
            upload: Upload::new(client, app_key, options)?,
            objects: Vec::new(),
        })
    }

    /// Returns the number of bytes remaining until reaching the optimal
    /// packed size. Adding objects larger than this will start a new slab.
    /// To minimize padding, prioritize objects that fit within the
    /// remaining size.
    pub fn remaining(&self) -> u64 {
        self.upload.remaining() as u64
    }

    /// Returns the cumulative length of all objects currently in the upload.
    pub fn length(&self) -> u64 {
        self.upload.length()
    }

    /// Returns the optimal size of each slab.
    pub fn optimal_data_size(&self) -> usize {
        self.upload.optimal_data_size()
    }

    /// Returns the number of slabs after the upload is finalized.
    pub fn slabs(&self) -> usize {
        self.length().div_ceil(self.optimal_data_size() as u64) as usize
    }

    /// Adds a new object to the upload. The data is read until EOF and packed into
    /// the current slab. Returns the number of bytes consumed; call
    /// [finalize](Self::finalize) once all objects have been added to get the
    /// resulting objects.
    ///
    /// If the reader errors part-way, it's safe to continue calling
    /// [add](Self::add); no object is registered for the failed call. Or call
    /// [finalize](Self::finalize) to collect the objects added so far.
    pub async fn add<R: AsyncRead + Unpin>(&mut self, r: R) -> Result<u64, UploadError> {
        let object = Object::default();

        let start = self.upload.length();
        let n = self.upload.read(&mut object.reader(r, 0)).await?;
        let end = self.upload.length();
        self.objects.push(ObjectUpload { start, end, object });
        Ok(n)
    }

    /// Finalizes the upload and returns the resulting objects. This will wait for all readers
    /// to finish and all slabs to be uploaded before returning. The resulting objects will contain the metadata needed to download the objects.
    ///
    /// The caller must pin the resulting objects to the indexer when ready.
    pub async fn finalize(self) -> Result<Vec<Object>, UploadError> {
        let optimal_data_size = self.optimal_data_size() as u64;
        let uploaded_slabs = self.upload.finish().await?;
        self.objects
            .into_iter()
            .map(|upload| {
                let mut object = upload.object;
                if upload.start == upload.end {
                    // empty object: nothing to splice in, leave it with zero slabs
                    return Ok(object);
                }
                let slabs = object.slabs_mut();
                let slabs_start = (upload.start / optimal_data_size) as usize;
                let slabs_end = upload.end.div_ceil(optimal_data_size) as usize;
                let n = slabs_end - slabs_start;
                slabs.extend_from_slice(&uploaded_slabs[slabs_start..slabs_end]);

                slabs[0].offset = (upload.start % optimal_data_size) as u32;
                if slabs.len() > 1 {
                    // if spanning multiple slabs, adjust first slab's length
                    slabs[0].length = (optimal_data_size - slabs[0].offset as u64) as u32;
                }
                let last_slab_index = n - 1;
                let last_slab_offset = slabs[last_slab_index].offset as u64;
                slabs[last_slab_index].length = (upload.end
                    - ((slabs_end as u64 - 1) * optimal_data_size)
                    - last_slab_offset) as u32;

                Ok(object)
            })
            .collect()
    }
}

/// Reads until EOF and uploads all slabs. The data will be erasure coded,
/// encrypted, and uploaded.
///
/// Pass [`Object::default()`] for new uploads. To resume a previous upload,
/// pass the object returned from the earlier call. Appending data changes
/// an object's ID. It must be re-pinned afterward and any references to
/// the previous ID must be updated.
pub(crate) async fn upload_object<R: AsyncRead + Unpin>(
    hosts: Hosts<Client>,
    app_key: Arc<AppKey>,
    mut object: Object,
    reader: R,
    options: UploadOptions,
) -> Result<Object, UploadError> {
    let reader = object.reader(reader, object.size());
    let new_slabs = upload_slabs(hosts, app_key, reader, options).await?;
    object.slabs_mut().extend(new_slabs);
    Ok(object)
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
