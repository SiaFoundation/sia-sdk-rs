use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use crate::congestion::{InflightController, SamplePermit};
use crate::encryption::{EncryptionKey, encrypt_shard};
use crate::erasure_coding::{self, ErasureCoder, ReadSlab, SlabReader};
use crate::hosts::{HostQueue, InflightGuard, QueueError, RPCError};
use crate::rhp4::Client;
use crate::slabs::SlabVersion;
use crate::task::AbortOnDropHandle;
use crate::time::{Duration, Elapsed, Instant, sleep};
use crate::{
    AppKey, Download, DownloadOptions, Hosts, Object, PackedUploadOptions, Sector, ShardProgress,
    ShardProgressCallback, Slab, UploadOptions,
};
use bytes::Bytes;
use log::debug;
use sia_core::rhp4::SECTOR_SIZE;
use sia_core::signing::PublicKey;
use thiserror::Error;
use tokio::io::{AsyncRead, BufReader};
use tokio::sync::{Notify, watch};
use tokio::task::JoinSet;

/// RAII increment of the pipeline's waiting-shard count. Held while a
/// shard has no upload attempt in flight (encode, encrypt, or a permit
/// wait) and dropped once it does, so the racing gate stays balanced
/// even when tasks are cancelled mid-wait.
struct WaitingGuard(watch::Sender<usize>);

impl WaitingGuard {
    fn new(waiting: watch::Sender<usize>) -> Self {
        // Only notify on the 0 boundary to avoid spurious wakes
        waiting.send_if_modified(|w| {
            *w = w.saturating_add(1);
            *w == 1
        });
        Self(waiting)
    }
}

impl Drop for WaitingGuard {
    fn drop(&mut self) {
        self.0.send_if_modified(|w| {
            *w = w.saturating_sub(1);
            *w == 0
        });
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
const RACE_FACTOR: f64 = 1.5;

const INITIAL_INFLIGHT: usize = 8;
const MIN_INFLIGHT: usize = 2;

#[cfg(not(target_arch = "wasm32"))]
fn default_slabs_in_memory(slab_size: usize) -> usize {
    (crate::default_memory_budget() / slab_size as u64).max(1) as usize
}

#[cfg(target_arch = "wasm32")]
fn default_slabs_in_memory(_slab_size: usize) -> usize {
    2
}

/// Gates concurrent shard uploads at the [`InflightController`]'s current
/// limit. Replaces a fixed semaphore so the limit can adapt while uploads are
/// in flight.
struct UploadLimiter {
    inflight: Mutex<usize>,
    /// Shards whose memory is committed but whose upload hasn't finished yet.
    /// Limits slab encoding so it can't runaway with memory that will sit idle.
    committed: Mutex<usize>,
    notify: Notify,
    /// Wakes the slab gate ([`Self::reserve`]) when the backlog drops or the
    /// limit grows.
    capacity: Notify,
    controller: InflightController,
}

impl UploadLimiter {
    fn new(initial: usize, floor: usize, cap: usize) -> Self {
        Self {
            inflight: Mutex::new(0),
            committed: Mutex::new(0),
            notify: Notify::new(),
            capacity: Notify::new(),
            // scale 1: the limited unit (a shard upload) is also the sampled unit
            controller: InflightController::new(initial, floor, cap, 1),
        }
    }

    /// Waits until the committed backlog leaves room for another slab, then
    /// commits `shards` and returns one [`ShardPermit`] per shard. The backlog
    /// is allowed to reach `limit + shards`. Enough to keep `limit` shards in
    /// flight plus one slab of lookahead, so slabs interleave within the memory
    /// budge.
    async fn reserve(self: &Arc<Self>, shards: usize) -> Vec<ShardPermit> {
        let notified = self.capacity.notified();
        tokio::pin!(notified);
        loop {
            // Register before checking so a wake between the check and the
            // await isn't lost.
            notified.as_mut().enable();
            {
                let mut committed = self.committed.lock().unwrap();
                // `limit + shards`: the in-flight target plus a slab of
                // lookahead. `+ shards <= cap`: the new slab must still fit the
                // memory budget. The first slab always fits since `shards <=
                // cap`, so a slab larger than the limit never deadlocks.
                if *committed < self.controller.limit() + shards
                    && *committed + shards <= self.controller.cap()
                {
                    *committed += shards;
                    return (0..shards)
                        .map(|_| ShardPermit {
                            limiter: self.clone(),
                        })
                        .collect();
                }
            }
            notified.as_mut().await;
            notified.set(self.capacity.notified());
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

    /// Issues a sampling token; capture it at dispatch and hand it back to
    /// [`Self::record`] on completion.
    fn sample(&self) -> SamplePermit {
        self.controller.sample()
    }

    /// Feeds a completion to the controller and wakes parked acquirers for any
    /// newly opened slots.
    fn record(&self, permit: SamplePermit, elapsed: Duration, ok: bool) {
        let delta = self.controller.record(permit, elapsed, ok);
        for _ in 0..delta.max(0) {
            self.notify.notify_one();
        }
        if delta > 0 {
            // the limit grew recheck the slab gate
            self.capacity.notify_one();
        }
    }
}

/// Permit for one shard-upload attempt. On drop — including task cancellation —
/// it releases the slot and wakes a waiter.
struct UploadPermit {
    limiter: Arc<UploadLimiter>,
}

impl Drop for UploadPermit {
    fn drop(&mut self) {
        *self.limiter.inflight.lock().unwrap() -= 1;
        self.limiter.notify.notify_one();
    }
}

/// Reservation for one buffered shard's memory, issued by
/// [`UploadLimiter::reserve`]. Held from encode until the shard's upload
/// finishes; on drop — including a failed or cancelled shard — it frees the
/// slot in the backlog and wakes the slab gate.
struct ShardPermit {
    limiter: Arc<UploadLimiter>,
}

impl Drop for ShardPermit {
    fn drop(&mut self) {
        *self.limiter.committed.lock().unwrap() -= 1;
        self.limiter.capacity.notify_one();
    }
}

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
            let _permit = permit;
            // Hold the inflight guard for the duration of the RPC so the
            // host's load is visible to concurrent pickers; dropped here
            // either after success or failure.
            let _inflight = inflight;
            let sample = limiter.sample();
            let start = Instant::now();
            let result = client
                .write_sector(host_key, &account_key.0, data, write_timeout)
                .await;
            let elapsed = start.elapsed();
            limiter.record(sample, elapsed, result.is_ok());
            let root = result
                .inspect_err(|e| {
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
        let race_timeout = self
            .client
            .write_estimate(self.data.len() as u32)
            .mul_f64(RACE_FACTOR);
        loop {
            tokio::select! {
                biased;
                Some(res) = tasks.join_next() => {
                    last_event = Instant::now();
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
                _ = async { let _ = waiting_rx.wait_for(|waiting| *waiting == 0).await; }, if !eligible => {
                    eligible = true;
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

    /// An internal task join error.
    #[error("join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    /// An error from the indexer API.
    #[error("api error: {0}")]
    ApiError(#[from] crate::app_client::Error),

    /// An error downloading existing data while merging an overwrite.
    #[error("download error: {0}")]
    Download(#[from] crate::DownloadError),

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
    /// Adaptive limit on shards in flight and buffered slabs
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
        Ok(Self {
            client,
            app_key,
            slab_buffer: Some(SlabReader::new(
                options.data_shards as usize,
                options.parity_shards as usize,
            )),
            erasure_coder: Arc::new(erasure_coder),
            limiter: Arc::new(UploadLimiter::new(
                INITIAL_INFLIGHT,
                MIN_INFLIGHT,
                max_buffered_slabs.saturating_mul(total_shards),
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
        let shard_permits = limiter.reserve(slab.shards.len()).await;
        // Count this slab's shards as waiting before the task spawns so the
        // racing gate can't open between buffering and encode.
        let waiting = self.waiting.clone();
        let waiting_guards: Vec<WaitingGuard> = slab
            .shards
            .iter()
            .map(|_| WaitingGuard::new(waiting.clone()))
            .collect();
        let handle = AbortOnDropHandle::new(maybe_spawn!(async move {
            let total_shards = slab.shards.len();

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
            let owned_slab_key = Arc::new(slab.encryption_key.clone());
            let mut shard_tasks: JoinSet<Result<SectorUploadResult, UploadError>> = JoinSet::new();
            for (((shard_index, mut shard), waiting_guard), shard_permit) in shards
                .into_iter()
                .enumerate()
                .zip(waiting_guards)
                .zip(shard_permits)
            {
                let owned_slab_key = owned_slab_key.clone();
                let shard_client = client.clone();
                let shard_account_key = app_key.clone();
                let limiter = limiter.clone();
                let hosts = hosts.clone();
                let waiting = waiting.clone();
                join_set_spawn!(shard_tasks, async move {
                    // Hold the memory reservation until the upload finishes (or
                    // this task is dropped), then release it on drop.
                    let _shard_permit = shard_permit;
                    let shard = maybe_spawn_blocking!({
                        encrypt_shard(&owned_slab_key, shard_index as u8, 0, &mut shard);
                        shard
                    });
                    let shard_upload = ShardUpload {
                        limiter,
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
                encryption_key: slab.encryption_key,
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
        data_key: EncryptionKey,
        mut reader: R,
    ) -> Result<u64, UploadError> {
        let mut total_length: u64 = 0;
        loop {
            let (n, slab) = self
                .slab_buffer
                .as_mut()
                .unwrap()
                .read_slab(data_key.clone(), &mut reader)
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
                version: SlabVersion::V1,
                encryption_key: slab.encryption_key,
                offset: 0,
                min_shards,
                length: slab.length,
                sectors: slab.shards.into_iter().map(|s| s.unwrap()).collect(),
            });
        }
        Ok(slabs)
    }

    /// Downloads `[offset, offset + len)` of `object` and feeds it into the
    /// pipeline. A no-op when `len` is 0.
    async fn feed_range(
        &mut self,
        object: &Object,
        data_key: &EncryptionKey,
        offset: u64,
        len: u64,
    ) -> Result<(), UploadError> {
        if len == 0 {
            return Ok(());
        }
        let download = Download::new(
            object,
            self.client.clone(),
            self.app_key.clone(),
            DownloadOptions {
                offset,
                length: Some(len),
                ..Default::default()
            },
        )?;
        self.read(data_key.clone(), download).await?;
        Ok(())
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
        options: PackedUploadOptions,
    ) -> Result<Self, UploadError> {
        Ok(Self {
            upload: Upload::new(client, app_key, options.into())?,
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
        // buffer the reader since SlabReader reads 64 bytes at a time
        let r = BufReader::new(r);
        let start = self.upload.length();
        let n = self.upload.read(object.data_key.clone(), r).await?;
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
                let slabs_start = (upload.start / optimal_data_size) as usize;
                let slabs_end = upload.end.div_ceil(optimal_data_size) as usize;
                let n = slabs_end - slabs_start;
                object
                    .slabs
                    .extend_from_slice(&uploaded_slabs[slabs_start..slabs_end]);

                object.slabs[0].offset = (upload.start % optimal_data_size) as u32;
                if object.slabs.len() > 1 {
                    // if spanning multiple slabs, adjust first slab's length
                    object.slabs[0].length =
                        (optimal_data_size - object.slabs[0].offset as u64) as u32;
                }
                let last_slab_index = n - 1;
                let last_slab_offset = object.slabs[last_slab_index].offset as u64;
                object.slabs[last_slab_index].length =
                    (upload.end - ((slabs_end as u64 - 1) * optimal_data_size) - last_slab_offset)
                        as u32;

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
    // buffer the reader since SlabReader reads 64 bytes at a time
    let reader = BufReader::new(reader);
    let Some(start_offset) = options.start_offset else {
        let mut upload = Upload::new(hosts, app_key, options)?;
        upload.read(object.data_key.clone(), reader).await?;
        object.slabs.extend(upload.finish().await?);
        return Ok(object);
    };

    let object_size = object.size();
    if start_offset > object_size {
        return Err(UploadError::OutOfRange(
            start_offset as usize,
            object_size as usize,
        ));
    }

    // Feed the existing head bytes, then the new data, then the existing tail
    // bytes into the pipeline; it re-chunks the whole stream into fresh slabs.
    let data_key = object.data_key.clone();
    let (head_index, head_start) = slab_at_offset(&object.slabs, start_offset);
    let mut upload = Upload::new(hosts, app_key, options)?;
    upload
        .feed_range(&object, &data_key, head_start, start_offset - head_start)
        .await?;
    let n = upload.read(data_key.clone(), reader).await?;
    if n == 0 {
        return Ok(object);
    }
    let end = start_offset + n;
    let (tail_index, tail_start) = slab_at_offset(&object.slabs, end);
    let mut replace_end = tail_index;
    if end < object_size && end > tail_start {
        let tail_end = tail_start + object.slabs[tail_index].length as u64;
        upload
            .feed_range(&object, &data_key, end, tail_end - end)
            .await?;
        replace_end += 1;
    }

    object
        .slabs
        .splice(head_index..replace_end, upload.finish().await?);
    Ok(object)
}

/// Returns the index of the slab containing `offset` and the object byte offset
/// at which that slab begins. If `offset` is at or past the end, returns
/// `(slabs.len(), object_size)`.
fn slab_at_offset(slabs: &[Slab], offset: u64) -> (usize, u64) {
    let mut start = 0u64;
    for (i, slab) in slabs.iter().enumerate() {
        let next = start + slab.length as u64;
        if offset < next {
            return (i, start);
        }
        start = next;
    }
    (slabs.len(), start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Host;
    use bytes::BytesMut;
    use rand::Rng;
    use sia_core::signing::PrivateKey;
    use sia_core::types::v2::{NetAddress, Protocol};
    use std::io::Cursor;

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
    async fn test_reserve_interleaves_a_lookahead_slab() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // The limit stays at 2 (no completions). The gate admits `limit +
        // shards` of backlog — the in-flight target plus a slab of lookahead —
        // so two 4-shard slabs fit before it parks, giving the slow pipe one
        // slab to interleave rather than stalling at a single slab.
        let limiter = Arc::new(UploadLimiter::new(2, 2, 100));
        let mut permits = limiter.reserve(4).await; // 0 -> 4
        permits.extend(limiter.reserve(4).await); // 4 -> 8: the lookahead slab still fits

        // A third reservation parks: committed 8 >= limit 2 + shards 4.
        let done = Arc::new(AtomicBool::new(false));
        let gate = limiter.clone();
        let flag = done.clone();
        maybe_spawn!(async move {
            let _permits = gate.reserve(4).await;
            flag.store(true, Ordering::SeqCst);
        });
        sleep(Duration::from_millis(50)).await;
        assert!(
            !done.load(Ordering::SeqCst),
            "reserve must park once the lookahead slab is buffered"
        );

        // Drop permits to drain below limit + shards (6); the parked
        // reservation resumes.
        for _ in 0..3 {
            permits.pop(); // 8 -> 5
        }
        sleep(Duration::from_millis(50)).await;
        assert!(
            done.load(Ordering::SeqCst),
            "reserve must resume once the backlog clears"
        );
    }

    #[sia_core_derive::cross_target_test]
    async fn test_reserve_caps_at_memory_budget() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // A tiny budget (cap = 2 shards) bounds the backlog even though the
        // limit's lookahead would otherwise admit more: only one 2-shard slab
        // fits at a time.
        let limiter = Arc::new(UploadLimiter::new(2, 2, 2));
        let permits = limiter.reserve(2).await; // 0 -> 2 (0 + 2 <= cap 2)

        // A second slab would exceed the budget (2 + 2 > 2), so it parks even
        // though committed (2) is still under limit + shards (4).
        let done = Arc::new(AtomicBool::new(false));
        let gate = limiter.clone();
        let flag = done.clone();
        maybe_spawn!(async move {
            let _permits = gate.reserve(2).await;
            flag.store(true, Ordering::SeqCst);
        });
        sleep(Duration::from_millis(50)).await;
        assert!(
            !done.load(Ordering::SeqCst),
            "reserve must park at the memory budget"
        );

        // Drop the permits; the budget now has room and the reservation resumes.
        drop(permits); // 2 -> 0
        sleep(Duration::from_millis(50)).await;
        assert!(
            done.load(Ordering::SeqCst),
            "reserve must resume once the budget frees"
        );
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

    /// Uploads `data`, overwrites `patch_len` bytes of value `patch_byte` at
    /// `offset`, then verifies the result downloads back to the expected bytes.
    /// Returns the (original, overwritten) objects for key assertions. Uses a
    /// fresh transport per call so each case's sectors are freed afterward.
    async fn overwrite_case(
        data: Bytes,
        offset: usize,
        patch_byte: u8,
        patch_len: usize,
    ) -> (Object, Object) {
        let options = UploadOptions::default();
        let transport = Client::new();
        let hosts = Hosts::new(transport.clone());
        hosts.update(
            (0..60)
                .map(|_| Host {
                    public_key: PrivateKey::from_seed(&rand::random()).public_key(),
                    addresses: vec![NetAddress {
                        protocol: Protocol::QUIC,
                        address: "localhost:1234".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                })
                .collect(),
            true,
        );
        let app_key = Arc::new(AppKey::import(rand::random()));

        let base = upload_object(
            hosts.clone(),
            app_key.clone(),
            Object::default(),
            Cursor::new(data.clone()),
            options.clone(),
        )
        .await
        .unwrap();

        let new = upload_object(
            hosts.clone(),
            app_key.clone(),
            base.clone(),
            Cursor::new(vec![patch_byte; patch_len]),
            UploadOptions {
                start_offset: Some(offset as u64),
                ..options
            },
        )
        .await
        .unwrap();

        let end = offset + patch_len;
        let mut expected = data.to_vec();
        if end > expected.len() {
            expected.resize(end, 0);
        }
        expected[offset..end]
            .iter_mut()
            .for_each(|b| *b = patch_byte);
        assert_eq!(new.size(), expected.len() as u64, "size");

        let mut recovered = Vec::with_capacity(expected.len());
        let mut download = Download::new(&new, hosts, app_key, DownloadOptions::default()).unwrap();
        tokio::io::copy(&mut download, &mut recovered)
            .await
            .unwrap();
        assert_eq!(expected, recovered, "content");
        (base, new)
    }

    /// Overwriting a byte range rewrites only the slabs it covers — merging the
    /// partial head and tail with existing data and re-keying them — across
    /// one-, two-, and three-slab spans, an aligned head, and an extension past
    /// the end, leaving untouched slabs (and their keys) intact.
    #[sia_core_derive::cross_target_test]
    async fn test_overwrite_object() {
        let optimal = UploadOptions::default().optimal_data_size();
        fn rand_bytes(n: usize) -> Bytes {
            let mut d = BytesMut::zeroed(n);
            rand::rng().fill_bytes(&mut d);
            d.freeze()
        }

        // one-slab span: overwrite inside the second slab; the first is kept.
        let (base, new) =
            overwrite_case(rand_bytes(optimal + 4096), optimal + 1000, 0xA1, 1000).await;
        assert_eq!(new.slabs().len(), 2);
        assert_eq!(
            new.slabs()[0].encryption_key,
            base.slabs()[0].encryption_key
        );
        assert_ne!(
            new.slabs()[1].encryption_key,
            base.slabs()[1].encryption_key
        );

        // two-slab span with an aligned head (no head download): start on slab
        // 1's boundary and run through it into slab 2; slab 0 is kept.
        let (base, new) =
            overwrite_case(rand_bytes(optimal * 2 + 4096), optimal, 0xB2, optimal + 100).await;
        assert_eq!(new.slabs().len(), 3);
        assert_eq!(
            new.slabs()[0].encryption_key,
            base.slabs()[0].encryption_key
        );
        assert_ne!(
            new.slabs()[1].encryption_key,
            base.slabs()[1].encryption_key
        );

        // three-slab span: head in slab 0, slab 1 fully overwritten (no
        // download), tail in slab 2.
        let (base, new) =
            overwrite_case(rand_bytes(optimal * 2 + 4096), 100, 0xC3, optimal * 2).await;
        assert_eq!(new.slabs().len(), 3);
        assert_ne!(
            new.slabs()[0].encryption_key,
            base.slabs()[0].encryption_key
        );

        // extend past the end: overwrite from inside the last slab beyond EOF.
        let (base, new) =
            overwrite_case(rand_bytes(optimal + 4096), optimal + 1000, 0xD4, 8192).await;
        assert_eq!(new.size(), (optimal + 1000 + 8192) as u64);
        assert_eq!(
            new.slabs()[0].encryption_key,
            base.slabs()[0].encryption_key
        );

        // end on a slab boundary: head in slab 1, overwrite ending exactly at the
        // start of slab 2, which must be left untouched (not re-keyed).
        let (base, new) = overwrite_case(
            rand_bytes(optimal * 2 + 4096),
            optimal + 1000,
            0xE5,
            optimal - 1000,
        )
        .await;
        assert_eq!(new.slabs().len(), 3);
        assert_eq!(
            new.slabs()[0].encryption_key,
            base.slabs()[0].encryption_key
        );
        assert_ne!(
            new.slabs()[1].encryption_key,
            base.slabs()[1].encryption_key
        );
        assert_eq!(
            new.slabs()[2].encryption_key,
            base.slabs()[2].encryption_key
        );

        // empty overwrite: a 0-byte patch is a no-op that leaves every slab
        // (and its key) untouched.
        let (base, new) = overwrite_case(rand_bytes(optimal + 4096), 1000, 0x00, 0).await;
        assert_eq!(new.slabs().len(), base.slabs().len());
        for (new_slab, base_slab) in new.slabs().iter().zip(base.slabs()) {
            assert_eq!(new_slab.encryption_key, base_slab.encryption_key);
        }
    }
}
