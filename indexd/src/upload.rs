use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use log::debug;
use sia::encryption::{EncryptionKey, encrypt_shard};
use sia::erasure_coding::{self, ErasureCoder};
use sia::rhp::{self, SECTOR_SIZE};
use sia::signing::{PrivateKey, PublicKey};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWriteExt, BufReader, SimplexStream, WriteHalf, copy, simplex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::{JoinSet, spawn_blocking};
use tokio::time::error::Elapsed;
use tokio::time::{Instant, sleep, timeout};
use tokio_util::task::AbortOnDropHandle;

use crate::hosts::{HostQueue, QueueError};
use crate::rhp4::RHP4Client;
use crate::{Hosts, Object, Sector, Slab};

#[derive(Debug, Error)]
pub enum UploadError {
    #[error("invalid options {0}")]
    InvalidOptions(String),

    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    #[error("rhp4 error: {0}")]
    Rhp4(#[from] crate::rhp4::Error),

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

impl Default for UploadOptions {
    fn default() -> Self {
        Self {
            data_shards: 10,
            parity_shards: 20,
            max_inflight: 16,
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
        self.upload_handle.abort();
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
pub(crate) struct Uploader<T: RHP4Client> {
    app_key: Arc<PrivateKey>,
    hosts: Hosts,
    transport: T,
}

impl<T> Uploader<T>
where
    T: RHP4Client + Send + Sync + Clone + 'static,
{
    pub fn new(hosts: Hosts, transport: T, app_key: Arc<PrivateKey>) -> Self {
        Uploader {
            app_key,
            hosts,
            transport,
        }
    }

    async fn upload_shard(
        transport: T,
        hosts: HostQueue,
        host_key: PublicKey,
        account_key: Arc<PrivateKey>,
        data: Bytes,
        write_timeout: Duration,
    ) -> Result<Sector, UploadError> {
        let now = Instant::now();
        let root = timeout(
            write_timeout,
            transport.write_sector(host_key, &account_key, data),
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

    #[allow(clippy::too_many_arguments)]
    async fn upload_slab_shard(
        permit: OwnedSemaphorePermit,
        transport: T,
        hosts: HostQueue,
        account_key: Arc<PrivateKey>,
        data: Bytes,
        slab_index: usize,
        shard_index: usize,
        progress_tx: Option<mpsc::UnboundedSender<()>>,
        initial_host: (PublicKey, usize),
    ) -> Result<(usize, Sector), UploadError> {
        let (host_key, attempts) = initial_host;
        let mut write_timeout = Self::upload_timeout(attempts); // mutable so that it can be adjusted on retries
        let mut tasks = JoinSet::new();
        tasks.spawn(Self::upload_shard(
            transport.clone(),
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
                            if let Some(progress_tx) = progress_tx {
                                let _ = progress_tx.send(());
                            }
                            return Ok((shard_index, sector));
                        }
                        Err(e) => {
                            debug!("slab {slab_index} shard {shard_index} upload failed {e:?}");
                            if tasks.is_empty() {
                                let (host_key, attempts) = hosts.pop_front()?;
                                write_timeout = Self::upload_timeout(attempts);
                                tasks.spawn(Self::upload_shard(transport.clone(), hosts.clone(), host_key, account_key.clone(), data.clone(), write_timeout));
                            }
                        }
                    }
                },
                _ = sleep(Duration::from_secs(active as u64)) => {
                    if let Ok(racer) = semaphore.clone().try_acquire_owned() {
                        // only race if there's an empty slot
                        let transport = transport.clone();
                        let data = data.clone();
                        let account_key = account_key.clone();
                        tasks.spawn(async move {
                            let _racer = racer; // hold the permit until the task completes
                            debug!("slab {slab_index} shard {shard_index} racing slow host");
                            let (host_key, attempts) = hosts.pop_front()?;
                            let write_timeout = Self::upload_timeout(attempts);
                            Self::upload_shard(transport.clone(), hosts.clone(), host_key, account_key, data, write_timeout).await
                        });
                    }
                }
            }
        }
    }

    async fn upload_slabs<R: AsyncRead + Unpin + Send + 'static>(
        transport: T,
        hosts: Hosts,
        app_key: Arc<PrivateKey>,
        r: R,
        options: UploadOptions,
    ) -> Result<Vec<Slab>, UploadError> {
        if options.data_shards == 0 {
            return Err(UploadError::InvalidOptions(
                "data_shards must be greater than 0".to_string(),
            ));
        } else if options.parity_shards == 0 {
            return Err(UploadError::InvalidOptions(
                "parity_shards must be greater than 0".to_string(),
            ));
        } else if options.max_inflight == 0 {
            return Err(UploadError::InvalidOptions(
                "max_inflight must be greater than 0".to_string(),
            ));
        }
        let data_shards = options.data_shards as usize;
        let parity_shards = options.parity_shards as usize;
        let total_shards = data_shards + parity_shards;

        // fail fast if there aren't enough hosts before doing any encoding
        if hosts.available_for_upload() < total_shards {
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
        let mut slab_upload_tasks = JoinSet::new();
        let rs = Arc::new(ErasureCoder::new(data_shards, parity_shards).unwrap());
        let mut slab_index: usize = 0;
        loop {
            let slab_permit = slab_sema.clone().acquire_owned().await?;
            let mut shards = vec![vec![0u8; SECTOR_SIZE]; total_shards];
            let length =
                ErasureCoder::read_slab_shards(&mut r, options.data_shards as usize, &mut shards)
                    .await?;
            if length == 0 {
                break; // EoF
            }

            let app_key = app_key.clone();
            let hosts = hosts.clone();
            let transport = transport.clone();
            let progress_tx = options.shard_uploaded.clone();
            let rs = rs.clone();
            let shard_sema = shard_sema.clone();

            slab_upload_tasks.spawn(async move {
                let _slab_guard = slab_permit;

                // note: it may seem like a good idea to start uploading the data shards
                // while the parity shards are being calculated, but this also forces
                // cloning the rather large shards and ends up being a net performance
                // decrease (~8%).
                //
                // It could probably be resolved by using a pool, but leaving that as a
                // future optimization for now.
                let shards = spawn_blocking(move || -> erasure_coding::Result<Vec<Vec<u8>>> {
                    rs.encode_shards(&mut shards)?;
                    Ok(shards)
                })
                .await??;

                // generate a unique encryption key for the slab
                let slab_key: EncryptionKey = rand::random::<[u8; 32]>().into();

                let host_queue = hosts.upload_queue();
                // reserve one host per shard upfront to guarantee each shard has at least one host
                let reserved_hosts = host_queue.pop_n(shards.len())?;
                let owned_slab_key = Arc::new(slab_key.clone());
                let start_time = Instant::now();
                let mut shard_upload_tasks = JoinSet::new();
                for (shard_index, mut shard) in shards.into_iter().enumerate() {
                    let app_key = app_key.clone();
                    let owned_slab_key = owned_slab_key.clone();
                    let permit = shard_sema.clone().acquire_owned().await?;
                    let transport = transport.clone();
                    let host_queue = host_queue.clone();
                    let progress_tx = progress_tx.clone();
                    let initial_host = reserved_hosts[shard_index];
                    // spawn a task to encrypt and upload each shard for this slab.
                    shard_upload_tasks.spawn(async move {
                        let shard = spawn_blocking(move || {
                            encrypt_shard(&owned_slab_key, shard_index as u8, 0, &mut shard);
                            shard
                        })
                        .await?;
                        Self::upload_slab_shard(
                            permit,
                            transport,
                            host_queue,
                            app_key,
                            shard.into(),
                            slab_index,
                            shard_index,
                            progress_tx,
                            initial_host,
                        )
                        .await
                    });
                }

                let mut slab_sectors = vec![None; data_shards + parity_shards];
                let mut remaining_shards = data_shards + parity_shards;
                while let Some(res) = shard_upload_tasks.join_next().await {
                    match res {
                        Ok(Ok((shard_index, sector))) => {
                            slab_sectors[shard_index] = Some(sector);
                            remaining_shards -= 1;
                            debug!("slab {slab_index} shard {shard_index} uploaded ({remaining_shards} remaining)");
                        },
                        Ok(Err(e)) => {
                            return Err(e);
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    };
                }
                debug!("slab {slab_index} uploaded in {:?}", Instant::now().duration_since(start_time));
                Ok((slab_index, Slab {
                    sectors: slab_sectors.into_iter().map(|s| s.unwrap()).collect(),
                    encryption_key: slab_key,
                    offset: 0,
                    length: length as u32,
                    min_shards: options.data_shards,
                }))
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

    /// Reads until EOF and uploads all slabs.
    /// The data will be erasure coded, encrypted,
    /// and uploaded using the uploader's parameters.
    ///
    /// # Arguments
    /// * `r` - The reader to read the data from. It will be read until EOF.
    /// * `options` - The [UploadOptions] to use for the upload.
    ///
    /// # Returns
    /// A new object containing the metadata needed to download the object. The caller
    /// must pin the object to an indexer after uploading.
    pub async fn upload<R: AsyncRead + Unpin + Send + 'static>(
        &self,
        r: R,
        options: UploadOptions,
    ) -> Result<Object, UploadError> {
        let mut object = Object::default();
        // use a buffered reader since the erasure coder reads 64 bytes at a time.
        let r = object.reader(BufReader::new(r), 0);
        let new_slabs = Self::upload_slabs(
            self.transport.clone(),
            self.hosts.clone(),
            self.app_key.clone(),
            r,
            options,
        )
        .await?;
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
        let transport = self.transport.clone();
        let hosts = self.hosts.clone();
        let app_key = self.app_key.clone();
        let (reader, writer) = simplex(1024 * 1024);
        PackedUpload {
            slab_size: options.data_shards as u64 * rhp::SECTOR_SIZE as u64,
            length: 0,
            writer,
            objects: Vec::new(),
            upload_handle: AbortOnDropHandle::new(tokio::spawn(async move {
                let slabs = Self::upload_slabs(transport, hosts, app_key, reader, options).await?;
                Ok(slabs)
            })),
        }
    }
}
