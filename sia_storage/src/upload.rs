use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use crate::congestion::InflightController;
use crate::encryption::{EncryptionKey, encrypt_shard};
use crate::erasure_coding::{self, ErasureCoder, ReadSlab, SlabReader};
use crate::hosts::{HostQueue, InflightGuard, QueueError, RPCError};
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
use tokio::sync::{Notify, Semaphore, watch};
use tokio::task::JoinSet;

/// RAII increment of the pipeline's waiting-shard count. Held while a
/// shard has no upload attempt in flight (encode, encrypt, or a permit
/// wait) and dropped once it does, so the racing gate stays balanced
/// even when tasks are cancelled mid-wait.
struct WaitingGuard(watch::Sender<usize>);

impl WaitingGuard {
    fn new(waiting: watch::Sender<usize>) -> Self {
        // Only notify on the 0 boundary: watchers gate on `waiting == 0`,
        // so intermediate transitions would wake every parked shard task
        // for nothing.
        waiting.send_if_modified(|w| {
            *w += 1;
            *w == 1
        });
        Self(waiting)
    }
}

impl Drop for WaitingGuard {
    fn drop(&mut self) {
        self.0.send_if_modified(|w| {
            *w -= 1;
            *w == 0
        });
    }
}

/// Starting inflight limit; slow start grows it quickly when uncongested.
const INITIAL_INFLIGHT: usize = 8;
/// Lower bound on the adaptive limit. Two permits keep a stuck tail
/// shard raceable.
const MIN_INFLIGHT: usize = 2;

#[cfg(not(target_arch = "wasm32"))]
fn default_slabs_in_memory(slab_size: usize) -> usize {
    let budget = crate::default_memory_budget();
    (budget / slab_size as u64).max(1) as usize
}

#[cfg(target_arch = "wasm32")]
fn default_slabs_in_memory(_slab_size: usize) -> usize {
    2
}

/// Gates concurrent shard uploads at the [`InflightController`]'s current
/// limit.
struct UploadLimiter {
    inflight: Mutex<usize>,
    notify: Notify,
    controller: InflightController,
}

impl UploadLimiter {
    fn new(initial: usize, floor: usize, cap: usize) -> Self {
        Self {
            inflight: Mutex::new(0),
            notify: Notify::new(),
            // scale 1: the limited unit (a shard upload) is also the sampled unit
            controller: InflightController::new(initial, floor, cap, 1),
        }
    }

    async fn acquire(self: &Arc<Self>) -> UploadPermit {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        loop {
            // Register before checking so a wake between the check and the
            // await isn't lost.
            notified.as_mut().enable();
            if let Some(permit) = self.try_acquire() {
                return permit;
            }
            notified.as_mut().await;
            notified.set(self.notify.notified());
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<UploadPermit> {
        let limit = self.controller.limit();
        let mut inflight = self.inflight.lock().unwrap();
        if *inflight < limit {
            *inflight += 1;
            Some(UploadPermit {
                limiter: self.clone(),
            })
        } else {
            None
        }
    }

    /// Feeds a completion to the controller and wakes parked acquirers for
    /// any newly opened slots.
    fn record(&self, expected: Option<Duration>, elapsed: Duration, ok: bool) {
        let delta = self.controller.record(expected, elapsed, ok);
        for _ in 0..delta.max(0) {
            self.notify.notify_one();
        }
    }
}

/// Permit for one shard-upload attempt. On drop — including task
/// cancellation — it releases the slot and wakes a waiter.
struct UploadPermit {
    limiter: Arc<UploadLimiter>,
}

impl Drop for UploadPermit {
    fn drop(&mut self) {
        *self.limiter.inflight.lock().unwrap() -= 1;
        self.limiter.notify.notify_one();
    }
}

struct ShardUpload {
    limiter: Arc<UploadLimiter>,
    client: Hosts<Client>,
    hosts: Arc<Mutex<HostQueue>>,
    account_key: Arc<AppKey>,
    data: Bytes,
    slab_index: usize,
    shard_index: usize,
    waiting: watch::Sender<usize>,
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
        inflight: InflightGuard,
        write_timeout: Duration,
        permit: UploadPermit,
    ) {
        let client = self.client.clone();
        let hosts = self.hosts.clone();
        let limiter = self.limiter.clone();
        let account_key = self.account_key.clone();
        let data = self.data.clone();
        let slab_index = self.slab_index;
        let shard_index = self.shard_index;
        join_set_spawn!(tasks, async move {
            // hold the guards for the duration of the RPC
            let _permit = permit;
            let _inflight = inflight;
            let expected = client.estimate_write_duration(&host_key, data.len() as u32);
            let now = Instant::now();
            let result = client
                .write_sector(host_key, &account_key.0, data, write_timeout)
                .await;
            let elapsed = now.elapsed();
            limiter.record(expected, elapsed, result.is_ok());
            let root = result.inspect_err(|e| {
                debug!(
                    "slab {slab_index} shard {shard_index} upload to host {host_key} failed after {elapsed:?} {e}",
                );
                hosts.lock().unwrap().retry(host_key);
            })?;
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

    /// Atomically pick the next-best host for this shard from the slab's
    /// pool and reserve an inflight slot on it. The returned guard must
    /// travel with the spawned write task so the reservation lives until
    /// the RPC finishes.
    fn pick_next_host(&self) -> Option<(PublicKey, InflightGuard)> {
        self.hosts.lock().unwrap().pick()
    }

    async fn upload_shard(
        self,
        waiting_guard: WaitingGuard,
    ) -> Result<SectorUploadResult, UploadError> {
        let permit = self.limiter.acquire().await;
        // This shard is about to have an attempt in flight; it no longer
        // blocks racing.
        drop(waiting_guard);
        let mut waiting_rx = self.waiting.subscribe();
        let (initial, initial_guard) = self.pick_next_host().ok_or(QueueError::NoMoreHosts)?;
        let mut tasks = JoinSet::new();
        self.spawn_write(&mut tasks, initial, initial_guard, UPLOAD_TIMEOUT, permit);
        let mut eligible = *waiting_rx.borrow_and_update() == 0;
        let mut last_event = Instant::now();

        let mut race_timeout = self.client.write_race_timeout(self.data.len() as u32);
        loop {
            tokio::select! {
                biased;
                Some(res) = tasks.join_next() => {
                    last_event = Instant::now();
                    race_timeout = self.client.write_race_timeout(self.data.len() as u32);
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
                            if tasks.is_empty() {
                                let (next, guard) = self.pick_next_host()
                                    .ok_or(QueueError::NoMoreHosts)?;
                                let permit = self.limiter.acquire().await;
                                self.spawn_write(&mut tasks, next, guard, UPLOAD_TIMEOUT, permit);
                            }
                        }
                    }
                },
                // Fires once racing will not steal work and no attempt has made progress for a race-timeout interval.
                _ = sleep((last_event + race_timeout).saturating_duration_since(Instant::now())), if eligible => {
                    let elapsed = last_event.elapsed();
                    last_event = Instant::now();
                    race_timeout = self.client.write_race_timeout(self.data.len() as u32);
                    eligible = *waiting_rx.borrow_and_update() == 0;
                    if eligible
                        && let Some(racer) = self.limiter.try_acquire()
                        && let Some((next, guard)) = self.pick_next_host() {
                            debug!(
                                "slab {} shard {} racing slow host with {next} after {:?}",
                                self.slab_index, self.shard_index, elapsed
                            );
                            self.spawn_write(&mut tasks, next, guard, UPLOAD_TIMEOUT, racer);
                        }
                },
                // `wait_for` re-checks inside the watch future, so this arm
                // only resolves on a real gate transition instead of waking
                // the loop for every counter change. `self.waiting` keeps
                // the channel open for the life of this loop, so it cannot
                // fail.
                // discard the returned Ref so the arm output doesn't hold a
                // borrow of the receiver
                _ = async { let _ = waiting_rx.wait_for(|waiting| *waiting == 0).await; }, if !eligible => {
                    eligible = true;
                    race_timeout = self.client.write_race_timeout(self.data.len() as u32);
                },
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
    /// Adaptive limit on the number of shards in flight at once.
    /// Separate from `slab_sema` since slabs can be buffered while waiting
    /// for shard uploads to complete, and we want to allow some buffering to
    /// improve performance.
    limiter: Arc<UploadLimiter>,
    /// Number of shards that do not yet have an upload attempt in flight.
    /// Shard tasks only race slow hosts while this is zero, so racers never
    /// take permits that a primary shard is waiting for.
    waiting: watch::Sender<usize>,
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

        let max_buffered_slabs = options
            .max_buffered_slabs
            .unwrap_or_else(|| default_slabs_in_memory(options.slab_size()));
        debug!("max_buffered_slabs {max_buffered_slabs}");
        Ok(Self {
            client,
            app_key,
            slab_buffer: Some(SlabReader::new(
                options.data_shards as usize,
                options.parity_shards as usize,
            )),
            erasure_coder: Arc::new(erasure_coder),
            slab_sema: Arc::new(Semaphore::new(max_buffered_slabs)),
            // The memory budget bounds shards in flight: at most every shard
            // of every buffered slab.
            limiter: Arc::new(UploadLimiter::new(
                INITIAL_INFLIGHT,
                MIN_INFLIGHT,
                max_buffered_slabs * total_shards,
            )),
            waiting: watch::channel(0).0,
            slab_tasks: VecDeque::new(),
            shard_uploaded: options.shard_uploaded,
        })
    }

    async fn spawn_slab(&mut self, slab: ReadSlab) -> Result<(), UploadError> {
        let client = self.client.clone();
        let rs = self.erasure_coder.clone();
        let limiter = self.limiter.clone();
        let app_key = self.app_key.clone();
        let progress_callback = self.shard_uploaded.clone();
        let slab_index = self.slab_tasks.len();
        let permit = self.slab_sema.clone().acquire_owned().await?;
        // Count this slab's shards as waiting before the task spawns so the
        // racing gate can't open between buffering and encode.
        let waiting = self.waiting.clone();
        let waiting_guards: Vec<WaitingGuard> = slab
            .shards
            .iter()
            .map(|_| WaitingGuard::new(waiting.clone()))
            .collect();
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
            // just-in-time via the slab's `HostQueue`, which scores by
            // `throughput / (inflight + 1)`. This disperses load across
            // hosts naturally — multiple slabs running in parallel won't
            // all pile onto the same top-N hosts, because by the time
            // slab N+1's shards pick, slab N's chosen hosts have higher
            // inflight and lower score.
            //
            // `HostQueue` also enforces slab uniqueness — every shard
            // within this slab must land on a distinct host (the indexer
            // rejects duplicate sectors because they break redundancy) —
            // while allowing failed hosts to be re-picked up to the slab's
            // retry cap.
            let hosts: Arc<Mutex<HostQueue>> = Arc::new(Mutex::new(client.upload_queue()));
            let owned_slab_key = Arc::new(slab_key.clone());
            let mut shard_tasks: JoinSet<Result<SectorUploadResult, UploadError>> = JoinSet::new();
            for ((shard_index, mut shard), waiting_guard) in
                shards.into_iter().enumerate().zip(waiting_guards)
            {
                let owned_slab_key = owned_slab_key.clone();
                let shard_client = client.clone();
                let shard_account_key = app_key.clone();
                let shard_limiter = limiter.clone();
                let hosts = hosts.clone();
                let waiting = waiting.clone();
                join_set_spawn!(shard_tasks, async move {
                    let shard = maybe_spawn_blocking!({
                        encrypt_shard(&owned_slab_key, shard_index as u8, 0, &mut shard);
                        shard
                    });
                    let shard_upload = ShardUpload {
                        limiter: shard_limiter,
                        client: shard_client,
                        account_key: shard_account_key,
                        data: Bytes::from(shard),
                        slab_index,
                        shard_index,
                        hosts,
                        waiting,
                    };
                    shard_upload.upload_shard(waiting_guard).await
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
    use crate::Host;
    use sia_core::signing::PrivateKey;
    use sia_core::types::v2::{NetAddress, Protocol};

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    fn opts(data: u8, parity: u8) -> UploadOptions {
        UploadOptions {
            data_shards: data,
            parity_shards: parity,
            ..Default::default()
        }
    }

    fn test_host(public_key: PublicKey) -> Host {
        Host {
            public_key,
            addresses: vec![NetAddress {
                protocol: Protocol::QUIC,
                address: "localhost:1234".to_string(),
            }],
            country_code: "US".to_string(),
            latitude: 0.0,
            longitude: 0.0,
            good_for_upload: true,
        }
    }

    /// Sets up five fast hosts with seeded write metrics plus one unsampled
    /// slow host. The discovery preference guarantees the slow host wins the
    /// initial pick, and the seeded p95 keeps the race timer near its 50ms
    /// floor so a racer (when allowed) beats the slow host comfortably.
    fn racing_setup(slow_delay: Duration) -> (Hosts<Client>, Arc<AppKey>, PublicKey) {
        let transport = Client::new();
        let hosts_manager = Hosts::new(transport.clone());
        let app_key = Arc::new(AppKey::import(rand::random()));
        let fast: Vec<PublicKey> = (0..5)
            .map(|_| PrivateKey::from_seed(&rand::random()).public_key())
            .collect();
        let slow = PrivateKey::from_seed(&rand::random()).public_key();
        hosts_manager.update(
            fast.iter()
                .chain(std::iter::once(&slow))
                .map(|pk| test_host(*pk))
                .collect(),
            true,
        );
        for pk in &fast {
            hosts_manager.record_write_sample(*pk, SECTOR_SIZE as u32, Duration::from_millis(10));
        }
        transport.set_slow_hosts([slow], slow_delay);
        (hosts_manager, app_key, slow)
    }

    fn shard_upload(
        hosts_manager: &Hosts<Client>,
        app_key: &Arc<AppKey>,
        waiting: &watch::Sender<usize>,
    ) -> ShardUpload {
        ShardUpload {
            limiter: Arc::new(UploadLimiter::new(4, 2, 4)),
            client: hosts_manager.clone(),
            hosts: Arc::new(Mutex::new(hosts_manager.upload_queue())),
            account_key: app_key.clone(),
            data: Bytes::from(vec![0u8; SECTOR_SIZE]),
            slab_index: 0,
            shard_index: 0,
            waiting: waiting.clone(),
        }
    }

    #[sia_core_derive::cross_target_test]
    async fn test_upload_race_gated_while_shards_waiting() {
        let (hosts_manager, app_key, slow) = racing_setup(Duration::from_millis(600));
        // another shard is still waiting for an attempt, so the slow initial
        // host must not be raced
        let (waiting, _) = watch::channel(1usize);
        let upload = shard_upload(&hosts_manager, &app_key, &waiting);
        let start = Instant::now();
        let result = upload
            .upload_shard(WaitingGuard::new(waiting.clone()))
            .await
            .unwrap();
        assert_eq!(
            result.sector.host_key, slow,
            "gated shard must finish on the slow host"
        );
        assert!(
            start.elapsed() >= Duration::from_millis(500),
            "gated shard must not race: {:?}",
            start.elapsed()
        );
    }

    #[sia_core_derive::cross_target_test]
    async fn test_upload_race_when_idle() {
        let (hosts_manager, app_key, slow) = racing_setup(Duration::from_millis(600));
        let (waiting, _) = watch::channel(0usize);
        let upload = shard_upload(&hosts_manager, &app_key, &waiting);
        let start = Instant::now();
        let result = upload
            .upload_shard(WaitingGuard::new(waiting.clone()))
            .await
            .unwrap();
        assert_ne!(
            result.sector.host_key, slow,
            "idle pipeline should race the slow host"
        );
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "racer should win quickly: {:?}",
            start.elapsed()
        );
    }

    #[sia_core_derive::cross_target_test]
    async fn test_upload_race_triggered_by_idle_transition() {
        let (hosts_manager, app_key, slow) = racing_setup(Duration::from_millis(1500));
        let (waiting, _) = watch::channel(1usize);
        // the "other" waiting shard starts its attempt 150ms in; the gate
        // opening should start racing immediately rather than waiting
        // another race-timeout interval
        let flip = waiting.clone();
        maybe_spawn!(async move {
            sleep(Duration::from_millis(150)).await;
            flip.send_modify(|w| *w -= 1);
        });
        let upload = shard_upload(&hosts_manager, &app_key, &waiting);
        let start = Instant::now();
        let result = upload
            .upload_shard(WaitingGuard::new(waiting.clone()))
            .await
            .unwrap();
        let elapsed = start.elapsed();
        assert_ne!(
            result.sector.host_key, slow,
            "race should start once the pipeline goes idle"
        );
        assert!(
            elapsed >= Duration::from_millis(140) && elapsed < Duration::from_millis(1000),
            "racer should win shortly after the gate opens: {elapsed:?}"
        );
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
