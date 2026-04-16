use std::collections::VecDeque;
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Poll, ready};

use crate::encryption::{Chacha20Cipher, EncryptionKey, encrypt_recovered_shards};
use crate::erasure_coding::{self, ErasureCoder};
use crate::hosts::{Hosts, RPCError};
use crate::rhp4::{Client, Transport};
use crate::time::{Duration, Elapsed, sleep};
use crate::{AppKey, Object, Sector, Slab};
use bytes::{Buf, Bytes, BytesMut};
use chacha20::cipher::StreamCipher;
use sia_core::rhp4::SEGMENT_SIZE;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
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
    NotEnoughShards(u8, u8),

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

/// Options for configuring a download.
pub struct DownloadOptions {
    /// Maximum number of concurrent chunk downloads. Defaults to 80.
    pub max_inflight: usize,
    /// Byte offset to start downloading from.
    pub offset: u64,
    /// Number of bytes to download. If `None`, downloads the entire object.
    pub length: Option<u64>,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            max_inflight: 80, // ~20 MiB in memory
            offset: 0,
            length: None,
        }
    }
}

struct SectorTask {
    sector: Sector,
    shard_index: usize,
}

struct AwaitingRecovery {
    sectors: Vec<SectorTask>,
}

struct ShardsRecovered {
    shard_offset: usize,
    shards: Vec<Option<BytesMut>>,
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
    client: Hosts<T>,
    account_key: Arc<AppKey>,

    min_shards: u8,
    encryption_key: EncryptionKey,
    offset: usize,
    length: usize,

    state: State,
}

impl<T: Transport> SlabRecovery<AwaitingRecovery, T> {
    fn new(client: Hosts<T>, account_key: Arc<AppKey>, slab: Slab) -> Result<Self, DownloadError> {
        if slab.min_shards == 0 {
            return Err(DownloadError::InvalidSlab(
                "min_shards cannot be 0".to_string(),
            ));
        } else if slab.min_shards as usize > slab.sectors.len() {
            return Err(DownloadError::InvalidSlab(format!(
                "min_shards {} cannot be greater than number of sectors {}",
                slab.min_shards,
                slab.sectors.len()
            )));
        }

        let mut sectors = slab
            .sectors
            .iter()
            .enumerate()
            .map(|(i, sector)| SectorTask {
                sector: sector.clone(),
                shard_index: i,
            })
            .collect::<Vec<_>>();
        client.prioritize(&mut sectors, |task| &task.sector.host_key);
        Ok(Self {
            client,
            account_key,
            min_shards: slab.min_shards,
            encryption_key: slab.encryption_key,
            offset: slab.offset as usize,
            length: slab.length as usize,
            state: AwaitingRecovery { sectors },
        })
    }

    async fn recover_shard(
        client: Hosts<T>,
        account_key: Arc<AppKey>,
        task: SectorTask,
        sector_offset: usize,
        sector_length: usize,
    ) -> Result<(usize, BytesMut), DownloadError> {
        let data = client
            .read_sector(
                task.sector.host_key,
                &account_key.0,
                task.sector.root,
                sector_offset,
                sector_length,
                // long to handle slow hosts, racing will ensure we don't waste time unnecessarily
                Duration::from_secs(60),
            )
            .await?;
        Ok((task.shard_index, data.try_into_mut().unwrap())) // no other references to the data exist, so this is safe
    }

    async fn recover_shards(self) -> Result<SlabRecovery<ShardsRecovered, T>, DownloadError> {
        let mut shard_tasks = JoinSet::new();
        let mut shards = vec![None; self.state.sectors.len()];
        let mut sectors = VecDeque::from(self.state.sectors);
        let min_shards = self.min_shards;
        let client = self.client;
        let account_key = self.account_key;
        let encryption_key = self.encryption_key;

        // compute the sector aligned region to download
        let chunk_size = SEGMENT_SIZE * self.min_shards as usize;
        let start = (self.offset / chunk_size) * SEGMENT_SIZE;
        let end = (self.offset + self.length).div_ceil(chunk_size) * SEGMENT_SIZE;
        let shard_offset = start;
        let shard_length = end - start;

        for i in 0..self.min_shards {
            let task = sectors
                .pop_front()
                .ok_or(DownloadError::NotEnoughShards(i, self.min_shards))?;
            join_set_spawn!(
                &mut shard_tasks,
                Self::recover_shard(
                    client.clone(),
                    account_key.clone(),
                    task,
                    shard_offset,
                    shard_length,
                )
            );
        }
        let mut recovered_shards: u8 = 0;

        loop {
            tokio::select! {
                Some(res) = shard_tasks.join_next() => {
                    match res? {
                        Ok((index, data)) => {
                            shards[index] = Some(data);
                            recovered_shards += 1;
                            if recovered_shards >= min_shards {
                                return Ok(SlabRecovery {
                                    client,
                                    account_key,
                                    min_shards,
                                    encryption_key,
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
                            if recovered_shards as usize + shard_tasks.len() + sectors.len() < min_shards as usize {
                                return Err(DownloadError::NotEnoughShards(recovered_shards, min_shards));
                            } else if let Some(task) = sectors.pop_front() {
                                join_set_spawn!(&mut shard_tasks, Self::recover_shard(client.clone(), account_key.clone(), task, shard_offset, shard_length));
                            }
                        }
                    }
                },
                _ = sleep(Duration::from_millis(500)), if !sectors.is_empty() => {
                    let task = sectors.pop_front().expect("sectors should not be empty");
                    join_set_spawn!(&mut shard_tasks, Self::recover_shard(client.clone(), account_key.clone(), task, shard_offset, shard_length));
                },
            }
        }
    }
}

impl<T: Transport> SlabRecovery<ShardsRecovered, T> {
    fn decode(self) -> Result<SlabRecovery<SlabDecoded, T>, DownloadError> {
        let parity_shards = self.state.shards.len() - self.min_shards as usize;
        let rs = ErasureCoder::new(self.min_shards as usize, parity_shards)?;
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
            .take(self.min_shards as usize)
            .map(|s| s.unwrap().freeze()) // safe because the data shards were just reconstructed
            .collect();
        Ok(SlabRecovery {
            client: self.client,
            account_key: self.account_key,
            min_shards: self.min_shards,
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

/// Downloads an object by recovering chunks of each slab in parallel and
/// writing them to the output writer in order.
///
/// note: this is pulled out for now to enable easier testing. In the future, when
/// we can mock the SDK, this should be moved directly into the Download method.
/// Iterator-like state for splitting slabs into chunks.
struct ChunkIter<const N: usize> {
    slabs: Vec<Slab>,
    slab_idx: usize,
    offset: u64,
    remaining: u64,
}

impl<const N: usize> ChunkIter<N> {
    fn new(slabs: Vec<Slab>, offset: u64, length: u64) -> Self {
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
        }
    }
}

impl<const N: usize> Iterator for ChunkIter<N> {
    type Item = Slab;

    fn next(&mut self) -> Option<Slab> {
        if self.remaining == 0 {
            return None;
        }
        let slab = &self.slabs[self.slab_idx];
        let slab_offset = slab.offset as u64 + self.offset;
        let slab_length = (slab.length as u64 - self.offset)
            .min(self.remaining)
            .min(N as u64);
        self.offset += slab_length;

        if self.offset >= slab.length as u64 {
            self.offset = 0;
            self.slab_idx += 1;
        }
        self.remaining -= slab_length;

        let mut chunk = slab.clone();
        chunk.offset = slab_offset as u32;
        chunk.length = slab_length as u32;
        Some(chunk)
    }
}

const CHUNK_SIZE: usize = 1 << 18; // 256 KiB

pub struct Download {
    hosts: Hosts<Client>,
    account_key: Arc<AppKey>,
    cipher: Chacha20Cipher,

    // download state
    buf: Bytes,
    queue: VecDeque<AbortOnDropHandle<Result<Vec<u8>, DownloadError>>>,
    chunk_iter: ChunkIter<CHUNK_SIZE>,
    // sticky error
    //
    // note: in Go we would store the error and return it, but that would
    // require all the enum variants to be Clone which is not the case, so
    // a generic variant is returned after the first error.
    errored: bool,
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
            self.spawn_next();
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

    fn spawn_next(&mut self) {
        if let Some(chunk_slab) = self.chunk_iter.next() {
            let hosts = self.hosts.clone();
            let account_key = self.account_key.clone();
            self.queue
                .push_back(AbortOnDropHandle::new(maybe_spawn!(async move {
                    let len = chunk_slab.length as usize;
                    let mut buf = Vec::with_capacity(len);
                    SlabRecovery::new(hosts, account_key, chunk_slab)?
                        .recover_shards()
                        .await?
                        .decode()?
                        .write(&mut buf)
                        .await?;
                    Ok(buf)
                })));
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
        self.spawn_next();
        self.cipher.apply_keystream(&mut result); // decrypt
        Ok(result)
    }

    pub(crate) fn new(
        object: &Object,
        hosts: Hosts<Client>,
        account_key: Arc<AppKey>,
        options: DownloadOptions,
    ) -> Result<Self, DownloadError> {
        if options.max_inflight == 0 {
            return Err(DownloadError::Custom(
                "max_inflight must be greater than 0".to_string(),
            ));
        }
        let object_size = object.size();
        let cipher = object.cipher(options.offset);
        let available = object_size.saturating_sub(options.offset);
        let remaining = options.length.unwrap_or(available).min(available);
        let slabs = object.slabs().to_vec();
        let chunk_iter = ChunkIter::new(slabs, options.offset, remaining);
        let mut download = Self {
            hosts,
            account_key,
            cipher,
            buf: Bytes::new(),
            queue: VecDeque::with_capacity(options.max_inflight),
            chunk_iter,
            errored: false,
        };
        for _ in 0..options.max_inflight {
            download.spawn_next();
        }
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

    use crate::compat::run_local;
    use crate::hosts::Hosts;
    use crate::upload::Uploader;
    use crate::{Host, UploadOptions};

    cross_target_tests! {
        async fn test_out_of_order_download() { run_local(async {
            let upload_options = UploadOptions::default();
            let slab_size = upload_options.data_shards as usize * SECTOR_SIZE;

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
            let mut data = BytesMut::zeroed(slab_size);
            rand::rng().fill_bytes(&mut data);
            let data = data.freeze();
            let app_key = Arc::new(AppKey::import(rand::random()));

            // configure decreasing per-sector read delays to force out-of-order
            // chunk completion during download
            transport.set_initial_read_delay(Duration::from_millis(500));

            let uploader = Uploader::new(hosts.clone(), app_key.clone());
            let obj = uploader
                .upload(Object::default(), Cursor::new(data.clone()), UploadOptions::default())
                .await
                .unwrap();

            let mut recovered_data = Vec::with_capacity(slab_size);
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
        }).await }

        async fn test_slab_recovery() { run_local(async {
            let upload_options = UploadOptions::default();
            let slab_size = upload_options.data_shards as usize * SECTOR_SIZE;

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
            let mut data = BytesMut::zeroed(slab_size);
            rand::rng().fill_bytes(&mut data);
            let data = data.freeze();
            let app_key = Arc::new(AppKey::import(rand::random()));

            let slabs = Uploader::upload_slabs(
                hosts.clone(),
                app_key.clone(),
                Cursor::new(data.clone()),
                upload_options,
            )
            .await
            .unwrap();

            let test_cases: Vec<(&str, usize, usize)> = vec![
                ("full slab", 0, slab_size),
                ("first half", 0, slab_size / 2),
                ("second half", slab_size / 2, slab_size / 2),
                ("first 30 bytes", 0, 30),
                ("middle 30 bytes", slab_size / 2 - 15, 30),
                ("last 30 bytes", slab_size - 30, 30),
                ("first 4KiB", 0, 4096),
                ("middle 4KiB", slab_size / 2 - 2048, 4096),
                ("last 4KiB", slab_size - 4096, 4096),
            ];

            for (name, offset, length) in test_cases {
                let mut slab = slabs[0].clone();
                slab.offset = offset as u32;
                slab.length = length as u32;

                let mut recovered_data = Vec::with_capacity(length);
                SlabRecovery::new(hosts.clone(), app_key.clone(), slab)
                    .unwrap()
                    .recover_shards()
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
        }).await }
    }
}
