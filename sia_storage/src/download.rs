use std::collections::VecDeque;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Poll, ready};

use crate::congestion::InflightController;
use crate::encryption::{Chacha20Cipher, EncryptionKey, encrypt_recovered_shards};
use crate::erasure_coding::{self, ErasureCoder};
use crate::hosts::{Hosts, InflightGuard, RPCError};
use crate::rhp4::{Client, Transport};
use crate::time::{Duration, Elapsed, Instant, sleep};
use crate::{AppKey, DownloadOptions, Object, Sector, ShardProgress, ShardProgressCallback, Slab};
use bytes::{Buf, Bytes};
use chacha20::cipher::StreamCipher;
use log::debug;
use sia_core::rhp4::SEGMENT_SIZE;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;

/// Errors that can occur during a download.
#[derive(Debug, Error)]
pub enum DownloadError {
    /// An I/O error occurred while writing the downloaded data.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The erasure decoder encountered an error.
    #[error("encoder error: {0}")]
    Encoder(#[from] erasure_coding::Error),

    /// Not enough shards were successfully downloaded to recover the data.
    #[error("not enough shards: {0}/{1}")]
    NotEnoughShards(usize, usize),

    /// The requested range is out of bounds.
    #[error("invalid range: {0}-{1}")]
    OutOfRange(usize, usize),

    /// A host RPC timed out.
    #[error("timeout error: {0}")]
    Timeout(#[from] Elapsed),

    /// An internal semaphore error.
    #[error("semaphore error: {0}")]
    SemaphoreError(#[from] tokio::sync::AcquireError),

    /// An internal task join error.
    #[error("join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    /// The slab metadata is invalid.
    #[error("invalid slab: {0}")]
    InvalidSlab(String),

    /// A host RPC error occurred during the download.
    #[error("rhp4 error: {0}")]
    RPC(#[from] RPCError),

    /// A custom error.
    #[error("custom error: {0}")]
    Custom(String),

    /// The download previously errored and can no longer be read from.
    #[error("download errored")]
    Errored,
}

struct SectorTask {
    sector: Sector,
    shard_index: usize,
}

/// A chunk may only race slow hosts while it is within `n` chunks of the read head.
/// Racing further ahead steals capacity from chunks the reader needs first.
const RACE_WINDOW: usize = 3;

/// Starting chunk limit; slow start grows it quickly when uncongested.
const INITIAL_INFLIGHT: usize = 8;
/// Lower bound on the adaptive limit. One chunk still fans out
/// `min_shards * 3 / 2` sector reads.
const MIN_INFLIGHT: usize = 1;

#[cfg(not(target_arch = "wasm32"))]
fn default_chunks_in_memory() -> usize {
    let budget = crate::default_memory_budget();
    (budget / MAX_CHUNK_SIZE as u64).max(1) as usize
}

#[cfg(target_arch = "wasm32")]
fn default_chunks_in_memory() -> usize {
    32
}

struct AwaitingRecovery {
    /// The sectors to download for this slab, paired with their inflight guards
    /// if they were reserved by `SlabRecovery::new`. Guards are held for the
    /// duration of the RPC in `SlabRecovery::recover_shard` to ensure the
    /// reservation is released on completion or error.
    sectors: Vec<(SectorTask, Option<InflightGuard>)>,
    /// This chunk's position in download order. Compared against `popped`
    /// to decide whether the chunk is close enough to the read head to race.
    seq: usize,
    /// Counts the chunks handed to the reader so far. `recover_shards`
    /// subscribes to it; holding a sender keeps the channel open so the
    /// `changed` arm cannot fail.
    popped: watch::Sender<usize>,
}

struct ShardsRecovered {
    shard_offset: usize,
    shards: Vec<Option<Vec<u8>>>,
}

struct SlabDecoded {
    data_shards: Vec<Bytes>,
}

/// State machine for recovering a slab. This provides a more structured
/// way to manage the process of downloading and decrypting shards. The primary
/// benefit is if we want to maintain a version of the download logic
/// for WASM, we can reuse the state machine and its await points and swap
/// out the async primitives.
struct SlabRecovery<State, T: Transport> {
    controller: Arc<InflightController>,
    client: Hosts<T>,
    account_key: Arc<AppKey>,

    slab_index: usize,
    min_shards: usize,
    encryption_key: EncryptionKey,
    offset: usize,
    length: usize,

    state: State,
}

impl<T: Transport> SlabRecovery<AwaitingRecovery, T> {
    fn new(
        client: Hosts<T>,
        account_key: Arc<AppKey>,
        slab: ChunkSlab,
        seq: usize,
        popped: watch::Sender<usize>,
        controller: Arc<InflightController>,
    ) -> Result<Self, DownloadError> {
        if slab.slab.min_shards == 0 {
            return Err(DownloadError::InvalidSlab(
                "min_shards cannot be 0".to_string(),
            ));
        } else if slab.slab.min_shards as usize > slab.slab.sectors.len() {
            return Err(DownloadError::InvalidSlab(format!(
                "min_shards {} cannot be greater than number of sectors {}",
                slab.slab.min_shards,
                slab.slab.sectors.len()
            )));
        }

        let mut sectors = slab
            .slab
            .sectors
            .iter()
            .enumerate()
            .map(|(i, sector)| SectorTask {
                sector: sector.clone(),
                shard_index: i,
            })
            .collect::<Vec<_>>();
        client.prioritize(&mut sectors, |task| &task.sector.host_key);

        // Reserve inflight slots for the top `min_shards` hosts now, while
        // we still hold the synchronous call frame. `Download::new` queues
        // many `SlabRecovery::new` calls back-to-back; without this, all of
        // them would prioritize against the same all-zero inflight
        // snapshot and pile onto the same fastest hosts. The guards travel
        // into the spawned read tasks via `recover_shards` and drop with
        // them; failure/timeout retries reserve on demand from `remaining`.
        let min_shards = slab.slab.min_shards as usize;
        let sectors = sectors
            .into_iter()
            .enumerate()
            .map(|(i, task)| {
                if i < min_shards {
                    let guard = client.reserve_inflight_download(&task.sector.host_key);
                    (task, guard)
                } else {
                    (task, None)
                }
            })
            .collect();

        Ok(Self {
            client,
            controller,
            account_key,
            slab_index: slab.index,
            min_shards,
            encryption_key: slab.slab.encryption_key,
            offset: slab.slab.offset as usize,
            length: slab.slab.length as usize,
            state: AwaitingRecovery {
                sectors,
                seq,
                popped,
            },
        })
    }

    fn recover_shard(
        &self,
        task: SectorTask,
        inflight: Option<InflightGuard>,
        shard_offset: usize,
        shard_length: usize,
    ) -> impl Future<Output = Result<(usize, Vec<u8>, ShardProgress), DownloadError>> + 'static
    {
        let client = self.client.clone();
        let controller = self.controller.clone();
        let account_key = self.account_key.clone();
        let slab_index = self.slab_index;
        async move {
            // Hold the inflight reservation for the duration of the RPC. The
            // guard was created by the caller before spawning so the load is
            // visible to concurrent `prioritize` calls, then dropped here on
            // either success or error.
            let _inflight = inflight;
            let expected =
                client.estimate_read_duration(&task.sector.host_key, shard_length as u32);
            let start = Instant::now();
            let result = client
                .read_sector(
                    task.sector.host_key,
                    &account_key.0,
                    task.sector.root,
                    shard_offset,
                    shard_length,
                    // long to handle slow hosts, racing will ensure we don't waste time unnecessarily
                    Duration::from_secs(60),
                )
                .await;
            let elapsed = start.elapsed();
            controller.record(expected, elapsed, result.is_ok());
            let data = result?;
            debug!(
                "slab {} shard {} recovered from {} in {:?}",
                slab_index, task.shard_index, task.sector.host_key, elapsed
            );
            // Bytes -> Vec<u8> is zero-copy when the Bytes is uniquely owned
            // (true here — no other refs to the response yet).
            Ok((
                task.shard_index,
                Vec::from(data),
                ShardProgress {
                    host_key: task.sector.host_key,
                    shard_size: shard_length,
                    shard_index: task.shard_index,
                    slab_index,
                    elapsed,
                },
            ))
        }
    }

    async fn recover_shards(
        mut self,
        shard_downloaded: Option<ShardProgressCallback>,
    ) -> Result<SlabRecovery<ShardsRecovered, T>, DownloadError> {
        let mut shard_tasks = JoinSet::new();
        let mut shards = vec![None; self.state.sectors.len()];
        let mut sectors = VecDeque::from(std::mem::take(&mut self.state.sectors));
        let seq = self.state.seq;
        let mut popped_rx = self.state.popped.subscribe();

        // compute the sector aligned region to download
        let min_shards = self.min_shards;
        let chunk_size = SEGMENT_SIZE * min_shards;
        let start = (self.offset / chunk_size) * SEGMENT_SIZE;
        let end = (self.offset + self.length).div_ceil(chunk_size) * SEGMENT_SIZE;
        let shard_offset = start;
        let shard_length = end - start;

        // overprovision the recovery to reduce tail latency from slow hosts
        let spawn_shards = (min_shards * 3 / 2).min(sectors.len());
        for i in 0..spawn_shards {
            let (task, inflight) = sectors
                .pop_front()
                .ok_or(DownloadError::NotEnoughShards(i, min_shards))?;
            join_set_spawn!(
                &mut shard_tasks,
                self.recover_shard(task, inflight, shard_offset, shard_length)
            );
        }
        let mut recovered_shards: usize = 0;
        let mut eligible = seq < *popped_rx.borrow_and_update() + RACE_WINDOW;
        let mut last_event = Instant::now();

        let mut race_timeout = self.client.read_race_timeout(shard_length as u32);
        loop {
            tokio::select! {
                Some(res) = shard_tasks.join_next() => {
                    last_event = Instant::now();
                    race_timeout = self.client.read_race_timeout(shard_length as u32);
                    match res? {
                        Ok((index, data, progress)) => {
                            shards[index] = Some(data);
                            recovered_shards += 1;
                            if recovered_shards <= min_shards && let Some(callback) = &shard_downloaded {
                                callback(progress);
                            }
                            if recovered_shards >= min_shards {
                                return Ok(SlabRecovery {
                                    client: self.client,
                                    controller: self.controller,
                                    account_key: self.account_key,
                                    min_shards,
                                    slab_index: self.slab_index,
                                    encryption_key: self.encryption_key,
                                    offset: self.offset,
                                    length: self.length,
                                    state: ShardsRecovered {
                                        shard_offset,
                                        shards,
                                    },
                                });
                            }
                        },
                        Err(_) => {
                            if recovered_shards + shard_tasks.len() + sectors.len() < min_shards {
                                return Err(DownloadError::NotEnoughShards(recovered_shards, min_shards));
                            } else if let Some((task, _)) = sectors.pop_front() {
                                let inflight = self.client.reserve_inflight_download(&task.sector.host_key);
                                join_set_spawn!(&mut shard_tasks, self.recover_shard(task, inflight, shard_offset, shard_length));
                            }
                        }
                    }
                },
                // Fires once racing will not steal work from more important chunks and the race timeout has elapsed
                _ = sleep((last_event + race_timeout).saturating_duration_since(Instant::now())), if eligible && !sectors.is_empty() => {
                    let elapsed = last_event.elapsed();
                    last_event = Instant::now();
                    let (task, _) = sectors.pop_front().expect("sectors should not be empty");
                    let inflight = self.client.reserve_inflight_download(&task.sector.host_key);
                    debug!("chunk {seq} racing slow host with {} after {:?}", task.sector.host_key, elapsed);
                    join_set_spawn!(&mut shard_tasks, self.recover_shard(task, inflight, shard_offset, shard_length));
                },
                // `wait_for` re-checks inside the watch future, so this arm
                // only resolves once the chunk actually enters the window
                // instead of waking the loop on every pop. Eligibility is
                // monotonic (`popped` only increases), so it never reverts.
                _ = popped_rx.wait_for(|popped| seq < *popped + RACE_WINDOW), if !eligible => {
                    eligible = true;
                    race_timeout = self.client.read_race_timeout(shard_length as u32);
                },
            }
        }
    }
}

impl<T: Transport> SlabRecovery<ShardsRecovered, T> {
    fn decode(self) -> Result<SlabRecovery<SlabDecoded, T>, DownloadError> {
        let parity_shards = self.state.shards.len() - self.min_shards;
        let rs = ErasureCoder::new(self.min_shards, parity_shards)?;
        let mut shards = self.state.shards;
        // decrypt the downloaded shards in place and recover the data shards
        encrypt_recovered_shards(
            &self.encryption_key,
            0,
            self.state.shard_offset,
            &mut shards,
        );
        rs.reconstruct_data_shards(&mut shards)?;
        let data_shards = shards
            .into_iter()
            .take(self.min_shards)
            .map(|s| Bytes::from(s.unwrap())) // safe: data shards were just reconstructed
            .collect();
        Ok(SlabRecovery {
            client: self.client,
            controller: self.controller,
            account_key: self.account_key,
            min_shards: self.min_shards,
            slab_index: self.slab_index,
            encryption_key: self.encryption_key,
            offset: self.offset,
            length: self.length,
            state: SlabDecoded { data_shards },
        })
    }
}

impl<T: Transport> SlabRecovery<SlabDecoded, T> {
    async fn write<W: AsyncWrite + Unpin>(self, w: &mut W) -> Result<(), DownloadError> {
        let skip = self.offset % (SEGMENT_SIZE * self.state.data_shards.len());
        ErasureCoder::write_data_shards(w, &self.state.data_shards, skip, self.length).await?;
        Ok(())
    }
}

pub(crate) struct ChunkSlab {
    slab: Slab,
    index: usize,
}

const INITIAL_CHUNK_SIZE: usize = 1 << 15; // 32 KiB
const MAX_CHUNK_SIZE: usize = 1 << 20; // 1 MiB

/// Iterator-like state for splitting slabs into chunks. The chunk size starts
/// at [`INITIAL_CHUNK_SIZE`] for a fast first byte and doubles per chunk up to
/// `SECTOR_SIZE`, so a long transfer settles into large reads without paying
/// that latency up front.
pub(crate) struct ChunkIter {
    slabs: Vec<Slab>,
    slab_idx: usize,
    offset: u64,
    remaining: u64,
    chunk_size: usize,
}

impl ChunkIter {
    pub(crate) fn new(slabs: Vec<Slab>, offset: u64, length: u64) -> Self {
        let mut slab_idx = 0;
        let mut offset = offset;
        while slab_idx < slabs.len() {
            let slab_length = slabs[slab_idx].length as u64;
            if offset < slab_length {
                break;
            }
            offset -= slab_length;
            slab_idx += 1;
        }
        Self {
            slabs,
            slab_idx,
            offset,
            remaining: length,
            chunk_size: INITIAL_CHUNK_SIZE,
        }
    }
}

impl Iterator for ChunkIter {
    type Item = ChunkSlab;

    fn next(&mut self) -> Option<ChunkSlab> {
        if self.remaining == 0 {
            return None;
        }
        let slab_index = self.slab_idx;
        let slab = &self.slabs[slab_index];
        let slab_offset = slab.offset as u64 + self.offset;
        let slab_length = (slab.length as u64 - self.offset)
            .min(self.remaining)
            .min(self.chunk_size as u64);
        self.offset += slab_length;

        if self.offset >= slab.length as u64 {
            self.offset = 0;
            self.slab_idx += 1;
        }
        self.remaining -= slab_length;
        self.chunk_size = self.chunk_size.saturating_mul(2).min(MAX_CHUNK_SIZE);

        let mut chunk = slab.clone();
        chunk.offset = slab_offset as u32;
        chunk.length = slab_length as u32;
        Some(ChunkSlab {
            slab: chunk,
            index: slab_index,
        })
    }
}

/// Downloads an object by recovering chunks of each slab in parallel and
/// writing them to the output writer in order.
///
/// note: this is pulled out for now to enable easier testing. In the future, when
/// we can mock the SDK, this should be moved directly into the Download method.
/// Initial per-chunk size. Kept small so the first chunk — and therefore the
/// first byte — lands in roughly one round trip.
pub struct Download {
    hosts: Hosts<Client>,
    account_key: Arc<AppKey>,
    cipher: Chacha20Cipher,

    // download state
    max_buffered_chunks: usize,
    buf: Bytes,
    queue: VecDeque<AbortOnDropHandle<Result<Vec<u8>, DownloadError>>>,
    chunk_iter: ChunkIter,
    /// Sequence number assigned to the next spawned chunk.
    next_seq: usize,
    /// Number of chunks handed to the reader so far. Chunk tasks watch this
    /// to decide whether they are within [`RACE_WINDOW`] of the read head.
    popped: watch::Sender<usize>,
    controller: Arc<InflightController>,
    // sticky error
    //
    // note: in Go we would store the error and return it, but that would
    // require all the enum variants to be Clone which is not the case, so
    // a generic variant is returned after the first error.
    errored: bool,

    shard_downloaded: Option<ShardProgressCallback>,
}

impl AsyncRead for Download {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.errored {
            return Poll::Ready(Err(std::io::Error::other(DownloadError::Errored)));
        }

        if !self.buf.is_empty() {
            self.drain_buf(buf);
            return Poll::Ready(Ok(()));
        }

        if let Some(chunk_handle) = self.queue.front_mut() {
            let mut result = match ready!(Pin::new(chunk_handle).poll(cx)) {
                Ok(Ok(data)) => data,
                Ok(Err(e)) => {
                    self.set_err();
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
                Err(e) => {
                    self.set_err();
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
            };
            self.queue.pop_front();
            self.popped.send_modify(|p| *p += 1);
            self.refill();
            self.cipher.apply_keystream(&mut result); // decrypt
            self.buf = Bytes::from(result);
            self.drain_buf(buf);
        }
        Poll::Ready(Ok(()))
    }
}

impl Download {
    fn drain_buf(&mut self, buf: &mut tokio::io::ReadBuf<'_>) {
        let to_copy = std::cmp::min(buf.remaining(), self.buf.len());
        buf.put_slice(&self.buf[..to_copy]);
        self.buf.advance(to_copy);
    }

    /// Marks the download as errored and aborts all in-flight chunk tasks.
    /// Subsequent reads will return [DownloadError::Errored].
    fn set_err(&mut self) {
        self.errored = true;
        self.buf = Bytes::new();
        self.queue.clear();
    }

    /// Spawns the next chunk recovery. Returns `false` once the chunk
    /// iterator is exhausted.
    fn spawn_next(&mut self) -> bool {
        let Some(chunk_slab) = self.chunk_iter.next() else {
            return false;
        };
        let hosts = self.hosts.clone();
        let account_key = self.account_key.clone();
        let shard_progress_callback = self.shard_downloaded.clone();
        // Build the SlabRecovery synchronously so prioritization and
        // top-K inflight reservations land before this method returns.
        // `Download::new` queues chunks back-to-back; each successive
        // `spawn_next` must see the previous chunk's reservations to
        // disperse picks across hosts.
        let len = chunk_slab.slab.length as usize;
        let seq = self.next_seq;
        self.next_seq += 1;
        let recovery = SlabRecovery::new(
            hosts,
            account_key,
            chunk_slab,
            seq,
            self.popped.clone(),
            self.controller.clone(),
        );
        self.queue
            .push_back(AbortOnDropHandle::new(maybe_spawn!(async move {
                let recovery = recovery?;
                let mut buf = Vec::with_capacity(len);
                recovery
                    .recover_shards(shard_progress_callback)
                    .await?
                    .decode()?
                    .write(&mut buf)
                    .await?;
                Ok(buf)
            })));
        true
    }

    /// Tops the chunk queue up to the controller's current limit.
    fn refill(&mut self) {
        while self.queue.len() < self.controller.limit().min(self.max_buffered_chunks) {
            if !self.spawn_next() {
                break;
            }
        }
    }

    /// Returns the next decoded chunk of data. Returns an empty `Vec` on EOF.
    /// Chunks are up to 256 KiB.
    ///
    /// This is primarily intended for FFI bindings to enable zero-copy
    /// transfer of an owned `Vec<u8>`. For general use, prefer the
    /// [AsyncRead] implementation.
    #[doc(hidden)]
    pub async fn read_chunk(&mut self) -> Result<Vec<u8>, DownloadError> {
        if self.errored {
            return Err(DownloadError::Errored);
        }
        // If a previous AsyncRead poll left a partial buffer, drain it first
        // so callers mixing read_chunk and poll_read don't lose data.
        if !self.buf.is_empty() {
            return Ok(std::mem::take(&mut self.buf).to_vec());
        }
        let Some(chunk_handle) = self.queue.pop_front() else {
            return Ok(Vec::new()); // EOF
        };
        self.popped.send_modify(|p| *p += 1);
        let mut result = match chunk_handle.await {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => {
                self.set_err();
                return Err(e);
            }
            Err(e) => {
                self.set_err();
                return Err(e.into());
            }
        };
        self.refill();
        self.cipher.apply_keystream(&mut result); // decrypt
        Ok(result)
    }

    pub(crate) fn new(
        object: &Object,
        hosts: Hosts<Client>,
        account_key: Arc<AppKey>,
        options: DownloadOptions,
    ) -> Result<Self, DownloadError> {
        if options.max_buffered_chunks == Some(0) {
            return Err(DownloadError::Custom(
                "max buffered chunks must be greater than 0".to_string(),
            ));
        }
        // The limit is in chunks but samples arrive per sector read, so a
        // window must span roughly min_shards completions per chunk.
        let scale = object
            .slabs()
            .first()
            .map(|s| s.min_shards as usize)
            .unwrap_or(1);
        // The memory budget caps buffered chunks; the controller adapts the
        // queue depth at or below it.
        let max_buffered_chunks = options
            .max_buffered_chunks
            .unwrap_or_else(default_chunks_in_memory);
        let controller = Arc::new(InflightController::new(
            INITIAL_INFLIGHT,
            MIN_INFLIGHT,
            max_buffered_chunks,
            scale,
        ));
        let object_size = object.size();
        let cipher = object.cipher(options.offset);
        let available = object_size.saturating_sub(options.offset);
        let remaining = options.length.unwrap_or(available).min(available);
        let slabs = object.slabs().to_vec();
        let chunk_iter = ChunkIter::new(slabs, options.offset, remaining);
        let max_buffered_chunks = options
            .max_buffered_chunks
            .unwrap_or_else(default_chunks_in_memory);
        debug!("max_buffered_chunks {max_buffered_chunks}");
        let mut download = Self {
            max_buffered_chunks,
            hosts,
            account_key,
            cipher,
            buf: Bytes::new(),
            queue: VecDeque::with_capacity(controller.limit()),
            chunk_iter,
            next_seq: 0,
            popped: watch::channel(0).0,
            controller,
            errored: false,
            shard_downloaded: options.shard_downloaded,
        };
        download.refill();
        Ok(download)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    use std::sync::Arc;

    use bytes::BytesMut;
    use rand::Rng;
    use sia_core::rhp4::SECTOR_SIZE;
    use sia_core::signing::PrivateKey;
    use sia_core::types::v2::NetAddress;

    use crate::hosts::Hosts;
    use crate::upload::{upload_object, upload_slabs};
    use crate::{Host, ShardProgress, UploadOptions};

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    fn test_controller() -> Arc<InflightController> {
        Arc::new(InflightController::new(
            INITIAL_INFLIGHT,
            MIN_INFLIGHT,
            100,
            10,
        ))
    }

    #[sia_core_derive::cross_target_test]
    async fn test_out_of_order_download() {
        let upload_options = UploadOptions::default();
        let optimal_data_size = upload_options.data_shards as usize * SECTOR_SIZE;

        let transport = Client::new();
        let hosts = Hosts::new(transport.clone());
        hosts.update(
            (0..60)
                .map(|_| Host {
                    public_key: PrivateKey::from_seed(&rand::random()).public_key(),
                    addresses: vec![NetAddress {
                        protocol: sia_core::types::v2::Protocol::QUIC,
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
        let mut data = BytesMut::zeroed(optimal_data_size);
        rand::rng().fill_bytes(&mut data);
        let data = data.freeze();
        let app_key = Arc::new(AppKey::import(rand::random()));

        // configure decreasing per-sector read delays to force out-of-order
        // chunk completion during download
        transport.set_initial_read_delay(Duration::from_millis(500));

        let obj = upload_object(
            hosts.clone(),
            app_key.clone(),
            Object::default(),
            Cursor::new(data.clone()),
            UploadOptions::default(),
        )
        .await
        .unwrap();

        let mut recovered_data = Vec::with_capacity(optimal_data_size);
        let mut download = Download::new(
            &obj,
            hosts.clone(),
            app_key.clone(),
            DownloadOptions::default(),
        )
        .unwrap();
        tokio::io::copy(&mut download, &mut recovered_data)
            .await
            .unwrap();

        assert_eq!(data, recovered_data);
    }

    #[sia_core_derive::cross_target_test]
    async fn test_slab_recovery() {
        let upload_options = UploadOptions::default();
        let optimal_data_size = upload_options.data_shards as usize * SECTOR_SIZE;

        let transport = Client::new();
        let hosts = Hosts::new(transport.clone());
        hosts.update(
            (0..60)
                .map(|_| Host {
                    public_key: PrivateKey::from_seed(&rand::random()).public_key(),
                    addresses: vec![NetAddress {
                        protocol: sia_core::types::v2::Protocol::QUIC,
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
        let mut data = BytesMut::zeroed(optimal_data_size);
        rand::rng().fill_bytes(&mut data);
        let data = data.freeze();
        let app_key = Arc::new(AppKey::import(rand::random()));

        let slabs = upload_slabs(
            hosts.clone(),
            app_key.clone(),
            Cursor::new(data.clone()),
            upload_options,
        )
        .await
        .unwrap();

        let test_cases: Vec<(&str, usize, usize)> = vec![
            ("full slab", 0, optimal_data_size),
            ("first half", 0, optimal_data_size / 2),
            ("second half", optimal_data_size / 2, optimal_data_size / 2),
            ("first 30 bytes", 0, 30),
            ("middle 30 bytes", optimal_data_size / 2 - 15, 30),
            ("last 30 bytes", optimal_data_size - 30, 30),
            ("first 4KiB", 0, 4096),
            ("middle 4KiB", optimal_data_size / 2 - 2048, 4096),
            ("last 4KiB", optimal_data_size - 4096, 4096),
        ];

        for (name, offset, length) in test_cases {
            let mut slab = slabs[0].clone();
            slab.offset = offset as u32;
            slab.length = length as u32;

            let mut recovered_data = Vec::with_capacity(length);
            SlabRecovery::new(
                hosts.clone(),
                app_key.clone(),
                ChunkSlab { slab, index: 0 },
                0,
                watch::channel(0).0,
                test_controller(),
            )
            .unwrap()
            .recover_shards(None)
            .await
            .unwrap()
            .decode()
            .unwrap()
            .write(&mut recovered_data)
            .await
            .unwrap();
            assert_eq!(
                &data[offset..offset + length],
                &recovered_data[..],
                "mismatch for case: {name}"
            );
        }
    }

    #[sia_core_derive::cross_target_test]
    async fn test_slab_recovery_progress_callback() {
        let upload_options = UploadOptions::default();
        let min_shards = upload_options.data_shards as usize;
        let total_shards = min_shards + upload_options.parity_shards as usize;
        let optimal_data_size = upload_options.optimal_data_size();
        let num_slabs = 3;

        let transport = Client::new();
        let hosts = Hosts::new(transport.clone());
        hosts.update(
            (0..60)
                .map(|_| Host {
                    public_key: PrivateKey::from_seed(&rand::random()).public_key(),
                    addresses: vec![NetAddress {
                        protocol: sia_core::types::v2::Protocol::QUIC,
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
        // upload enough data for multiple slabs
        let data_size = optimal_data_size * num_slabs;
        let mut data = BytesMut::zeroed(data_size);
        rand::rng().fill_bytes(&mut data);
        let data = data.freeze();
        let app_key = Arc::new(AppKey::import(rand::random()));

        let obj = upload_object(
            hosts.clone(),
            app_key.clone(),
            Object::default(),
            Cursor::new(data.clone()),
            upload_options,
        )
        .await
        .unwrap();
        assert_eq!(obj.slabs().len(), num_slabs);

        // download with progress callback
        let progress: Arc<std::sync::Mutex<Vec<ShardProgress>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let progress_clone = progress.clone();
        let opts = DownloadOptions::default().on_shard_downloaded(move |p: ShardProgress| {
            progress_clone.lock().unwrap().push(p);
        });

        let mut recovered_data = Vec::with_capacity(data_size);
        let mut download = Download::new(&obj, hosts.clone(), app_key.clone(), opts).unwrap();
        tokio::io::copy(&mut download, &mut recovered_data)
            .await
            .unwrap();
        assert_eq!(data, recovered_data);

        let events = progress.lock().unwrap();
        // the chunk size ramps, so chunks per slab isn't uniform; replay the
        // same iterator the downloader uses to count them. each chunk recovers
        // min_shards shards independently.
        let total_chunks = ChunkIter::new(obj.slabs().to_vec(), 0, data_size as u64).count();
        let expected_total = total_chunks * min_shards;
        assert_eq!(
            events.len(),
            expected_total,
            "expected {expected_total} progress callbacks ({total_chunks} chunks × {min_shards} shards), got {}",
            events.len()
        );

        // count callbacks per slab, verify shard metadata
        let mut per_slab: std::collections::HashMap<usize, usize> =
            std::collections::HashMap::new();
        for event in events.iter() {
            assert!(
                event.shard_size > 0 && event.shard_size <= SECTOR_SIZE,
                "shard_size {} out of range",
                event.shard_size
            );
            assert!(
                event.shard_index < total_shards,
                "shard_index {} out of range for total_shards {}",
                event.shard_index,
                total_shards
            );
            *per_slab.entry(event.slab_index).or_default() += 1;
        }
        // every slab should have at least one callback
        for slab_idx in 0..num_slabs {
            assert!(
                per_slab.contains_key(&slab_idx),
                "slab {slab_idx} had no progress callbacks"
            );
        }
    }

    /// Uploads one slab to 60 hosts, then seeds fast read samples for the
    /// first 15 sector hosts so they deterministically win `prioritize`
    /// (the rest only have write samples from the upload) and the read median
    /// sits at its floor, and finally makes those 15 hosts slow. Racers
    /// (when allowed) come from the remaining fast hosts.
    async fn racing_setup(slow_delay: Duration) -> (Hosts<Client>, Arc<AppKey>, Slab) {
        let upload_options = UploadOptions::default();
        let optimal_data_size = upload_options.data_shards as usize * SECTOR_SIZE;

        let transport = Client::new();
        let hosts = Hosts::new(transport.clone());
        hosts.update(
            (0..60)
                .map(|_| Host {
                    public_key: PrivateKey::from_seed(&rand::random()).public_key(),
                    addresses: vec![NetAddress {
                        protocol: sia_core::types::v2::Protocol::QUIC,
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
        let mut data = BytesMut::zeroed(optimal_data_size);
        rand::rng().fill_bytes(&mut data);
        let data = data.freeze();
        let app_key = Arc::new(AppKey::import(rand::random()));

        let slabs = upload_slabs(
            hosts.clone(),
            app_key.clone(),
            Cursor::new(data),
            upload_options,
        )
        .await
        .unwrap();
        let slab = slabs[0].clone();

        let slow_set: Vec<_> = slab.sectors.iter().take(15).map(|s| s.host_key).collect();
        for host_key in &slow_set {
            hosts.record_read_sample(*host_key, 1 << 18, Duration::from_micros(1));
        }
        transport.set_slow_hosts(slow_set, slow_delay);
        (hosts, app_key, slab)
    }

    fn racing_chunk(slab: &Slab) -> ChunkSlab {
        let mut chunk = slab.clone();
        chunk.offset = 0;
        chunk.length = 1 << 18;
        ChunkSlab {
            slab: chunk,
            index: 0,
        }
    }

    #[sia_core_derive::cross_target_test]
    async fn test_download_race_gated_outside_window() {
        let (hosts, app_key, slab) = racing_setup(Duration::from_millis(1500)).await;
        let start = Instant::now();
        SlabRecovery::new(
            hosts.clone(),
            app_key.clone(),
            racing_chunk(&slab),
            RACE_WINDOW, // first chunk outside the window
            watch::channel(0).0,
            test_controller(),
        )
        .unwrap()
        .recover_shards(None)
        .await
        .unwrap();
        assert!(
            start.elapsed() >= Duration::from_millis(1200),
            "chunk outside the window must not race: {:?}",
            start.elapsed()
        );
    }

    #[sia_core_derive::cross_target_test]
    async fn test_download_race_within_window() {
        let (hosts, app_key, slab) = racing_setup(Duration::from_millis(1500)).await;
        let start = Instant::now();
        SlabRecovery::new(
            hosts.clone(),
            app_key.clone(),
            racing_chunk(&slab),
            0,
            watch::channel(0).0,
            test_controller(),
        )
        .unwrap()
        .recover_shards(None)
        .await
        .unwrap();
        assert!(
            start.elapsed() < Duration::from_millis(1200),
            "chunk at the read head should race slow hosts: {:?}",
            start.elapsed()
        );
    }

    #[sia_core_derive::cross_target_test]
    async fn test_download_race_triggered_by_window() {
        let (hosts, app_key, slab) = racing_setup(Duration::from_millis(1500)).await;
        let popped_tx = watch::channel(0).0;
        // the reader pops a chunk 200ms in, bringing this chunk into the
        // window; racing should begin immediately rather than waiting
        // another race-timeout interval
        let tx = popped_tx.clone();
        maybe_spawn!(async move {
            sleep(Duration::from_millis(200)).await;
            tx.send_modify(|p| *p += 1);
        });
        let start = Instant::now();
        SlabRecovery::new(
            hosts.clone(),
            app_key.clone(),
            racing_chunk(&slab),
            RACE_WINDOW,
            popped_tx,
            test_controller(),
        )
        .unwrap()
        .recover_shards(None)
        .await
        .unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(190) && elapsed < Duration::from_millis(1200),
            "racing should begin once the chunk enters the window: {elapsed:?}"
        );
    }
}
