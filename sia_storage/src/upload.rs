use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use crate::encryption::{EncryptionKey, encrypt_shards};
use crate::erasure_coding::{self, ErasureCoder, SlabReader, read_slabs};
use crate::hosts::{HostQueue, Hosts, QueueError, RPCError};
use crate::time::{Duration, Elapsed, Instant, sleep};
use crate::{Object, Sector, Slab};
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use log::debug;
use sia_core::rhp4::{SECTOR_SIZE, SEGMENT_SIZE};
use sia_core::signing::{PrivateKey, PublicKey};
use thiserror::Error;
use tokio::io::{AsyncRead, BufReader};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

struct ShardUpload {
    semaphore: Arc<Semaphore>,
    client: Hosts,
    hosts: HostQueue,
    account_key: Arc<PrivateKey>,
    data: Bytes,
    slab_index: usize,
    shard_index: usize,
}

impl ShardUpload {
    fn upload_timeout(attempts: usize) -> Duration {
        Duration::from_secs((10 + (5 * attempts as u64)).min(120))
    }

    fn spawn_write(
        &self,
        host_key: PublicKey,
        write_timeout: Duration,
        permit: OwnedSemaphorePermit,
    ) -> impl Future<Output = Result<SectorUploadResult, UploadError>> {
        let client = self.client.clone();
        let hosts = self.hosts.clone();
        let account_key = self.account_key.clone();
        let data = self.data.clone();
        let slab_index = self.slab_index;
        let shard_index = self.shard_index;
        async move {
            let _permit = permit;
            let now = Instant::now();
            let root = client.write_sector(host_key, &account_key, data, write_timeout).await
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
            Ok(SectorUploadResult { sector: Sector { root, host_key }, shard_index, slab_index })
        }
    }

    async fn upload_shard(
        self,
        initial_host: (PublicKey, usize),
    ) -> Result<SectorUploadResult, UploadError> {
        let (host_key, attempts) = initial_host;
        let write_timeout = Self::upload_timeout(attempts);
        let permit = self.semaphore.clone().acquire_owned().await?;
        let mut tasks = FuturesUnordered::new();
        tasks.push(self.spawn_write(host_key, write_timeout, permit));
        loop {
            let active = tasks.len();
            tokio::select! {
                Some(res) = tasks.next() => {
                    match res {
                        Ok(result) => {
                            if result.sector.host_key != host_key {
                                debug!("slab {} shard {} penalizing original host {}", self.slab_index, self.shard_index, host_key);
                                self.client.add_failure(host_key)
                            }
                            /*if let Some(progress_tx) = progress_tx {
                                let _ = progress_tx.send(());
                            }*/
                            return Ok(result);
                        }
                        Err(_) => {
                            if tasks.is_empty() {
                                let (host_key, attempts) = self.hosts.pop_front()?;
                                let write_timeout = Self::upload_timeout(attempts);
                                let permit = self.semaphore.clone().acquire_owned().await?;
                                tasks.push(self.spawn_write(host_key, write_timeout, permit));
                            }
                        }
                    }
                },
                _ = sleep(Duration::from_secs(active as u64)) => {
                    if let Ok(racer) = self.semaphore.clone().try_acquire_owned()
                        && let Ok((host_key, attempts)) = self.hosts.pop_front() {
                            debug!("slab {} shard {} racing slow host", self.slab_index, self.shard_index);
                            let write_timeout = Self::upload_timeout(attempts);
                            tasks.push(self.spawn_write(host_key, write_timeout, racer));
                        }
                }
            }
        }
    }
}

struct SectorUploadResult {
    sector: Sector,
    shard_index: usize,
    slab_index: usize,
}

#[derive(Debug, Error)]
pub enum UploadError {
    #[error("invalid options {0}")]
    InvalidOptions(String),

    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    #[error("rhp4 error: {0}")]
    RPC(#[from] RPCError),

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

pub struct UploadOptions {
    pub data_shards: u8,
    pub parity_shards: u8,
    pub max_inflight: usize,

    /// Optional channel to notify when each shard is uploaded.
    /// This can be used to implement progress reporting.
    pub shard_uploaded: Option<mpsc::UnboundedSender<()>>,
}

impl UploadOptions {
    pub fn optimal_data_size(&self) -> u64 {
        SECTOR_SIZE as u64 * self.data_shards as u64
    }

    pub fn slab_size(&self) -> u64 {
        SECTOR_SIZE as u64 * (self.data_shards as u64 + self.parity_shards as u64)
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
    start: usize,
    end: usize,
    object: Object,
}

/// A packed upload allows multiple objects to be uploaded together in a single upload. This can be more
/// efficient than uploading each object separately if the size of the object is less than the minimum
/// slab size.
///
/// The caller must call [finalize](Self::finalize) to complete the upload.
pub struct PackedUpload {
    slab_buffer: SlabReader,
    total_length: usize,
    upload_pipeline: UploadPipeline,
    objects: Vec<ObjectUpload>,
}

impl PackedUpload {
    pub(crate) fn new(
        client: Hosts,
        app_key: Arc<PrivateKey>,
        options: UploadOptions,
    ) -> Result<Self, UploadError> {
        Ok(Self {
            slab_buffer: SlabReader::new(
                options.data_shards as usize,
                options.parity_shards as usize,
            ),
            total_length: 0,
            upload_pipeline: UploadPipeline::new(client, app_key, options)?,
            objects: Vec::new(),
        })
    }

    /// Returns the number of bytes remaining until reaching the optimal
    /// packed size. Adding objects larger than this will start a new slab.
    /// To minimize padding, prioritize objects that fit within the
    /// remaining size.
    pub fn remaining(&self) -> usize {
        self.slab_buffer
            .slab_size()
            .saturating_sub(self.slab_buffer.length())
    }

    /// Returns the cumulative length of all objects currently in the upload.
    pub fn length(&self) -> usize {
        self.total_length
    }

    /// Returns the optimal size of each slab.
    pub fn slab_size(&self) -> usize {
        self.slab_buffer.slab_size()
    }

    /// Returns the number of slabs after the upload is finalized.
    pub fn slabs(&self) -> usize {
        self.length().div_ceil(self.slab_size())
    }

    /// Adds a new object to the upload. The data will be read until EOF and packed into
    /// the upload. The resulting object will contain the metadata needed to download the object. The caller
    /// must call [finalize](Self::finalize) to get the resulting objects after all objects have been added.
    pub async fn add<R: AsyncRead + Unpin>(&mut self, r: R) -> Result<usize, UploadError> {
        let data_shards = self.upload_pipeline.erasure_coder.data_shards();
        let stripe_size = SEGMENT_SIZE * data_shards;
        let object = Object::default();
        let mut r = BufReader::with_capacity(4 * stripe_size, object.reader(r, 0));
        let start = self.total_length;
        loop {
            tokio::select! {
                biased;
                Some(res) = self.upload_pipeline.poll_next() => {
                    res?;
                },
                res = self.slab_buffer.read_slab(&mut r) => {
                    let read_bytes = res?;
                    if read_bytes == 0 {
                        break;
                    }
                    if let Some(slab) = self.slab_buffer.next_slab() {
                        self.upload_pipeline.push(slab.shards, slab.length);
                    }
                    self.total_length += read_bytes;
                }
            }
        }
        let end = self.total_length;
        self.objects.push(ObjectUpload { start, end, object });
        Ok(end - start)
    }

    pub async fn finalize(mut self) -> Result<Vec<Object>, UploadError> {
        let slab_size = self.slab_size();
        if let Some(slab) = self.slab_buffer.finish() {
            self.upload_pipeline.push(slab.shards, slab.length);
        }
        let uploaded_slabs = self.upload_pipeline.finish().await?;
        self.objects
            .into_iter()
            .map(|upload| {
                let mut object = upload.object;
                let slabs = object.slabs_mut();
                let slabs_start = upload.start / slab_size;
                let slabs_end = upload.end.div_ceil(slab_size);
                let n = slabs_end - slabs_start;
                slabs.extend_from_slice(&uploaded_slabs[slabs_start..slabs_end]);

                slabs[0].offset = (upload.start % slab_size) as u32;
                if slabs.len() > 1 {
                    // if spanning multiple slabs, adjust first slab's length
                    slabs[0].length = (slab_size - slabs[0].offset as usize) as u32;
                }
                let last_slab_index = n - 1;
                let last_slab_offset = slabs[last_slab_index].offset as usize;
                slabs[last_slab_index].length =
                    (upload.end - ((slabs_end - 1) * slab_size) - last_slab_offset) as u32;

                Ok(object)
            })
            .collect()
    }
}

struct UploadedSlab {
    encryption_key: EncryptionKey,
    length: u32,
    shards: Vec<Option<Sector>>,
}

enum PipelineEvent {
    SlabEncoded {
        slab_index: usize,
        shards: Vec<Bytes>,
        slab_key: EncryptionKey,
        length: usize,
    },
    ShardUploaded(SectorUploadResult),
}

type PipelineFuture = crate::compat::BoxFuture<'static, Result<PipelineEvent, UploadError>>;

pub(crate) struct UploadPipeline {
    client: Hosts,
    app_key: Arc<PrivateKey>,
    erasure_coder: Arc<ErasureCoder>,
    shard_sema: Arc<Semaphore>,
    tasks: FuturesUnordered<PipelineFuture>,
    slabs: BTreeMap<usize, UploadedSlab>,
    next_slab_index: usize,
}

impl UploadPipeline {
    pub(crate) fn new(
        client: Hosts,
        app_key: Arc<PrivateKey>,
        options: UploadOptions,
    ) -> Result<Self, UploadError> {
        let total_shards = options.data_shards as usize + options.parity_shards as usize;
        if client.available_for_upload() < total_shards {
            return Err(UploadError::InvalidOptions(format!(
                "not enough hosts for upload: need {}, have {}",
                total_shards,
                client.available_for_upload()
            )));
        }
        Ok(Self {
            client,
            app_key,
            erasure_coder: Arc::new(
                ErasureCoder::new(options.data_shards as usize, options.parity_shards as usize)
                    .map_err(|e| {
                        UploadError::InvalidOptions(format!(
                            "failed to create erasure coder: {}",
                            e
                        ))
                    })?,
            ),
            shard_sema: Arc::new(Semaphore::new(options.max_inflight)),
            tasks: FuturesUnordered::new(),
            slabs: BTreeMap::new(),
            next_slab_index: 0,
        })
    }

    fn handle_event(&mut self, event: PipelineEvent) -> Result<Option<()>, UploadError> {
        match event {
            PipelineEvent::ShardUploaded(result) => {
                self.slabs
                    .entry(result.slab_index)
                    .and_modify(|s| s.shards[result.shard_index] = Some(result.sector));
                Ok(Some(()))
            }
            PipelineEvent::SlabEncoded {
                slab_index,
                shards,
                slab_key,
                length,
            } => {
                self.slabs.insert(
                    slab_index,
                    UploadedSlab {
                        encryption_key: slab_key,
                        length: length as u32,
                        shards: vec![None; shards.len()],
                    },
                );
                let total_shards = shards.len();
                let hosts = self.client.upload_queue();
                let initial_hosts = hosts.pop_n(total_shards)?;
                for shard_index in 0..total_shards {
                    let initial_host = initial_hosts[shard_index];
                    let shard_upload = ShardUpload {
                        semaphore: self.shard_sema.clone(),
                        client: self.client.clone(),
                        hosts: hosts.clone(),
                        account_key: self.app_key.clone(),
                        data: shards[shard_index].clone(),
                        slab_index,
                        shard_index,
                    };
                    self.tasks.push(Box::pin(async move {
                        shard_upload
                            .upload_shard(initial_host)
                            .await
                            .map(PipelineEvent::ShardUploaded)
                    }));
                }
                Ok(None)
            }
        }
    }

    /// Polls for the next completed shard upload. Encoding completions are
    /// handled internally — shard futures are pushed and the poll continues.
    pub(crate) async fn poll_next(&mut self) -> Option<Result<(), UploadError>> {
        loop {
            match self.tasks.next().await? {
                Err(e) => return Some(Err(e)),
                Ok(event) => match self.handle_event(event) {
                    Ok(Some(())) => return Some(Ok(())),
                    Ok(None) => continue,
                    Err(e) => return Some(Err(e)),
                },
            }
        }
    }

    /// Queues a new slab for encoding and upload. This is non-blocking — the
    /// actual encoding and uploads are driven by [poll_next](Self::poll_next).
    pub(crate) fn push(&mut self, shards: Vec<BytesMut>, length: usize) {
        let total_shards = self.erasure_coder.total_shards();
        if shards.len() != total_shards {
            panic!("expected {} shards, got {}", total_shards, shards.len());
        }
        let slab_index = self.next_slab_index;
        self.next_slab_index += 1;
        let rs = self.erasure_coder.clone();
        self.tasks.push(Box::pin(async move {
            let (shards, slab_key) = maybe_spawn_blocking!({
                let start = Instant::now();
                let slab_key: EncryptionKey = rand::random::<[u8; 32]>().into();
                let mut shards = shards;
                rs.encode_shards(&mut shards)?;
                encrypt_shards(&slab_key, 0, 0, &mut shards);
                debug!(
                    "slab {} encoded and encrypted slab in {:?}",
                    slab_index,
                    start.elapsed()
                );
                Ok::<_, UploadError>((
                    shards
                        .into_iter()
                        .map(|shard| shard.freeze())
                        .collect::<Vec<_>>(),
                    slab_key,
                ))
            })?;
            Ok(PipelineEvent::SlabEncoded {
                slab_index,
                shards,
                slab_key,
                length,
            })
        }));
    }

    /// Waits for all pending uploads to complete and returns the resulting slabs.
    pub(crate) async fn finish(mut self) -> Result<Vec<Slab>, UploadError> {
        while let Some(result) = self.tasks.next().await {
            self.handle_event(result?)?;
        }

        Ok(self
            .slabs
            .into_values()
            .map(|slab| Slab {
                encryption_key: slab.encryption_key,
                offset: 0,
                min_shards: self.erasure_coder.data_shards() as u8,
                length: slab.length,
                sectors: slab.shards.into_iter().map(|s| s.unwrap()).collect(),
            })
            .collect::<Vec<_>>())
    }
}

struct EncodedSlab {
    slab_key: EncryptionKey,
    slab_index: usize,
    shards: Vec<Bytes>,
    length: usize,
}

pub(crate) async fn upload_slabs<R: AsyncRead + Unpin> (mut r: R, client: Hosts, app_key: Arc<PrivateKey>, options: UploadOptions) -> Result<Vec<Slab>, UploadError> {
    let total_shards = options.data_shards as usize + options.parity_shards as usize;
    if client.available_for_upload() < total_shards {
        return Err(UploadError::InvalidOptions(format!(
            "not enough hosts for upload: need {}, have {}",
            total_shards,
            client.available_for_upload()
        )));
    }
    let data_shards = options.data_shards as usize;
    let parity_shards = options.parity_shards as usize;

    let erasure_coder = Arc::new(ErasureCoder::new(options.data_shards as usize, options.parity_shards as usize)?);
    let shard_sema = Arc::new(Semaphore::new(options.max_inflight));
    let mut slab_tasks = FuturesUnordered::new();
    let mut shard_tasks = FuturesUnordered::new();
    let mut slab_reader = Box::pin(read_slabs(&mut r, data_shards, parity_shards));
    let mut slabs = BTreeMap::new();
    let mut current_slab_index: usize = 0;
    loop {
        tokio::select! {
            Some(res) = shard_tasks.next() => {
                let result: SectorUploadResult = res?;
                slabs.entry(result.slab_index).and_modify(|s: &mut UploadedSlab| s.shards[result.shard_index] = Some(result.sector));
            }
            Some(res) = slab_tasks.next() => {
                let encoded_slab: EncodedSlab = res?;
                let total_shards = encoded_slab.shards.len();
                let hosts = client.upload_queue();
                let initial_hosts = hosts.pop_n(total_shards)?;
                slabs.insert(encoded_slab.slab_index, UploadedSlab {
                    encryption_key: encoded_slab.slab_key,
                    length: encoded_slab.length as u32,
                    shards: vec![None; total_shards],
                });
                for shard_index in 0..total_shards {
                    let initial_host = initial_hosts[shard_index];
                    let shard_upload = ShardUpload {
                        semaphore: shard_sema.clone(),
                        client: client.clone(),
                        hosts: hosts.clone(),
                        account_key: app_key.clone(),
                        data: encoded_slab.shards[shard_index].clone(),
                        slab_index: encoded_slab.slab_index,
                        shard_index,
                    };
                    shard_tasks.push(async move {
                        shard_upload
                            .upload_shard(initial_host)
                            .await
                    });
                }
            }
            Some(res) = slab_reader.next(), if shard_tasks.len() < options.max_inflight => {
                let (length, mut shards) = res?;
                let slab_key: EncryptionKey = rand::random::<[u8; 32]>().into();
                let slab_index = current_slab_index;
                current_slab_index += 1;

                let erasure_coder = erasure_coder.clone();
                slab_tasks.push(async move {
                    let start = Instant::now();
                    let (shards, slab_key) = maybe_spawn_blocking!({
                        erasure_coder.encode_shards(&mut shards)?;
                        encrypt_shards(&slab_key, 0, 0, &mut shards);
                        debug!(
                            "slab {} encoded and encrypted slab in {:?}",
                            slab_index,
                            start.elapsed()
                        );
                        Ok::<_, UploadError>((
                            shards
                                .into_iter()
                                .map(|shard| shard.freeze())
                                .collect::<Vec<_>>(),
                            slab_key,
                        ))
                    })?;
                    Ok::<_, UploadError>(EncodedSlab{
                        slab_key,
                        slab_index,
                        shards,
                        length,
                    })
                });
            },
            else => break,
        }
    }

    Ok(slabs.into_values().map(|slab| Slab {
        encryption_key: slab.encryption_key,
        offset: 0,
        min_shards: data_shards as u8,
        length: slab.length,
        sectors: slab.shards.into_iter().map(|s| s.unwrap()).collect(),
    }).collect())
}