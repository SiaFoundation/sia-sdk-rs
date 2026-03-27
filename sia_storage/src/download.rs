use std::collections::VecDeque;
use std::fmt::Debug;
use std::sync::Arc;

use crate::encryption::{EncryptionKey, encrypt_shards};
use crate::erasure_coding::{self, ErasureCoder};
use crate::hosts::{Hosts, RPCError};
use crate::time::{Duration, Elapsed, Instant, sleep};
use crate::{Object, Sector, Slab};
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use futures::stream::{FuturesOrdered, FuturesUnordered};
use log::debug;
use sia_core::rhp4::SEGMENT_SIZE;
use sia_core::signing::PrivateKey;
use thiserror::Error;
use tokio::io::AsyncWrite;
use tokio::sync::Semaphore;

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encoder error: {0}")]
    Encoder(#[from] erasure_coding::Error),

    #[error("not enough shards: {0}/{1}")]
    NotEnoughShards(u8, u8),

    #[error("invalid range: {0}-{1}")]
    OutOfRange(usize, usize),

    #[error("timeout error: {0}")]
    Timeout(#[from] Elapsed),

    #[error("semaphore error: {0}")]
    SemaphoreError(#[from] tokio::sync::AcquireError),

    #[error("join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("invalid slab: {0}")]
    InvalidSlab(String),

    #[error("rhp4 error: {0}")]
    RPC(#[from] RPCError),

    #[error("custom error: {0}")]
    Custom(String),
}

pub struct DownloadOptions {
    /// Maximum number of concurrent chunk downloads.
    pub max_inflight: usize,
    pub offset: u64,
    pub length: Option<u64>,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            max_inflight: 100, // ~120 MiB in memory
            offset: 0,
            length: None,
        }
    }
}

struct AwaitingRecovery {
    sectors: Vec<Sector>,
}

struct ShardsRecovered {
    shard_offset: usize,
    shards: Vec<Option<BytesMut>>,
}

struct SlabDecoded {
    data_shards: Vec<Bytes>,
}

struct SlabRecovery<T> {
    client: Hosts,
    account_key: Arc<PrivateKey>,

    min_shards: u8,
    encryption_key: EncryptionKey,
    offset: usize,
    length: usize,

    state: T,
}

impl SlabRecovery<AwaitingRecovery> {
    fn new(client: Hosts, account_key: Arc<PrivateKey>, slab: Slab) -> Self {
        Self {
            client,
            account_key,
            min_shards: slab.min_shards,
            encryption_key: slab.encryption_key,
            offset: slab.offset as usize,
            length: slab.length as usize,
            state: AwaitingRecovery {
                sectors: slab.sectors,
            },
        }
    }

    async fn recover_shard(
        client: Hosts,
        account_key: Arc<PrivateKey>,
        sector: Sector,
        sector_offset: usize,
        sector_length: usize,
        shard_index: usize,
    ) -> Result<(usize, BytesMut), DownloadError> {
        let data = client
            .read_sector(
                sector.host_key,
                &account_key,
                sector.root,
                sector_offset,
                sector_length,
                // long to handle slow hosts, racing will ensure we don't waste time unnecessarily
                Duration::from_secs(60),
            )
            .await?;
        Ok((shard_index, data.try_into_mut().unwrap())) // no other references to the data exist, so this is safe
    }

    async fn recover_shards(self) -> Result<SlabRecovery<ShardsRecovered>, DownloadError> {
        let mut shard_tasks = FuturesUnordered::new();
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

        for shard_index in 0..self.min_shards {
            let sector = sectors
                .pop_front()
                .expect("not enough sectors to satisfy min_shards");
            shard_tasks.push(Self::recover_shard(
                client.clone(),
                account_key.clone(),
                sector,
                shard_offset,
                shard_length,
                shard_index as usize,
            ));
        }
        let mut shard_index = min_shards;
        let mut recovered_shards: u8 = 0;

        loop {
            tokio::select! {
                biased;
                Some(res) = shard_tasks.next() => {
                    match res {
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
                            } else if let Some(sector) = sectors.pop_front() {
                                shard_tasks.push(Self::recover_shard(client.clone(), account_key.clone(), sector, shard_offset, shard_length, shard_index as usize));
                                shard_index += 1;
                            }
                        }
                    }
                },
                _ = sleep(Duration::from_secs(1)), if !sectors.is_empty() => {
                    let sector = sectors.pop_front().expect("not enough sectors to satisfy min_shards");
                    shard_tasks.push(Self::recover_shard(client.clone(), account_key.clone(), sector, shard_offset, shard_length, shard_index as usize));
                    shard_index += 1;
                },
            }
        }
    }
}

impl SlabRecovery<ShardsRecovered> {
    async fn decode(self) -> Result<SlabRecovery<SlabDecoded>, DownloadError> {
        let parity_shards = self.state.shards.len() - self.min_shards as usize;
        let rs = ErasureCoder::new(self.min_shards as usize, parity_shards).unwrap(); // should never fail
        let mut shards = self.state.shards;
        // recover the data shards and decrypt them in place.
        rs.reconstruct_data_shards(&mut shards).unwrap(); // should never fail
        let mut shards = shards
            .into_iter()
            .take(self.min_shards as usize)
            .map(|x| x.unwrap())
            .collect::<Vec<_>>();
        encrypt_shards(
            &self.encryption_key,
            0,
            self.state.shard_offset,
            &mut shards,
        );

        Ok(SlabRecovery {
            client: self.client,
            account_key: self.account_key,
            min_shards: self.min_shards,
            encryption_key: self.encryption_key,
            offset: self.offset,
            length: self.length,
            state: SlabDecoded {
                data_shards: shards.into_iter().map(|x| x.freeze()).collect(),
            },
        })
    }
}

impl SlabRecovery<SlabDecoded> {
    async fn write<W: AsyncWrite + Unpin>(self, w: &mut W) -> Result<(), DownloadError> {
        let skip = self.offset % (SEGMENT_SIZE * self.state.data_shards.len());
        ErasureCoder::write_data_shards(w, &self.state.data_shards, skip, self.length).await?;
        Ok(())
    }
}

pub(crate) async fn download_object<W: AsyncWrite + Unpin>(
    hosts: Hosts,
    account_key: Arc<PrivateKey>,
    w: &mut W,
    object: &Object,
    options: DownloadOptions,
) -> Result<(), DownloadError> {
    const CHUNK_SIZE: usize = 1 << 19; // 512 KiB

    let mut w = object.writer(w, 0);
    let semaphore = Arc::new(Semaphore::new(options.max_inflight));
    let mut offset = options.offset;
    let mut remaining = options.length.unwrap_or(object.size());
    let slabs = object.slabs();

    // skip slabs before the starting offset
    let mut slab_idx = 0;
    while slab_idx < slabs.len() {
        let slab_length = slabs[slab_idx].length as u64;
        if offset < slab_length {
            break;
        }
        offset -= slab_length;
        slab_idx += 1;
    }

    let mut chunk_tasks = FuturesOrdered::new();
    loop {
        tokio::select! {
            biased;

            Some(res) = chunk_tasks.next() => {
                let chunk: SlabRecovery<SlabDecoded> = res?;
                chunk.write(&mut w).await?;
            },

            permit = semaphore.clone().acquire_owned(), if remaining > 0 && slab_idx < slabs.len() => {
                let permit = permit?;
                let slab = &slabs[slab_idx];
                let slab_offset = slab.offset as u64 + offset;
                let slab_length = (slab.length as u64 - offset).min(remaining).min(CHUNK_SIZE as u64);
                offset += slab_length;

                // advance to next slab if we've consumed this one
                if offset >= slab.length as u64 {
                    offset = 0;
                    slab_idx += 1;
                }
                remaining -= slab_length;

                let mut slab = slab.clone();
                slab.offset = slab_offset as u32;
                slab.length = slab_length as u32;

                let hosts = hosts.clone();
                let account_key = account_key.clone();
                chunk_tasks.push_back(async move {
                    let _permit = permit;
                    let start = Instant::now();
                    let slab_recovery = SlabRecovery::new(hosts, account_key, slab)
                        .recover_shards()
                        .await
                        .inspect_err(|e| debug!("slab {slab_idx} chunk {offset}` failed to recover shards {:?}", e))?
                        .decode()
                        .await
                        .inspect_err(|e| debug!("slab {slab_idx} chunk {offset}` failed to decode {:?}", e))?;
                        debug!("slab {slab_idx} chunk {offset} recovered in {:?}", start.elapsed());
                        Ok::<_, DownloadError>(slab_recovery)
                });
            },
            else => break,
        }
    }
    Ok(())
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
    use crate::rhp4::Client;
    use crate::upload::upload_slabs;
    use crate::{Host, UploadOptions};

    #[tokio::test]
    async fn test_slab_recovery() {
        const DATA_SHARDS: usize = 10;
        const PARITY_SHARDS: usize = 4;
        const SLAB_SIZE: usize = SECTOR_SIZE * DATA_SHARDS;

        let hosts = Hosts::new(Client::new());
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
        let mut data = BytesMut::zeroed(SLAB_SIZE);
        rand::rng().fill_bytes(&mut data);
        let data = data.freeze();
        let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));

        let slabs = upload_slabs(
            Cursor::new(data.clone()),
            hosts.clone(),
            app_key.clone(),
            UploadOptions {
                data_shards: DATA_SHARDS as u8,
                parity_shards: PARITY_SHARDS as u8,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let test_cases: Vec<(&str, usize, usize)> = vec![
            ("full slab", 0, SLAB_SIZE),
            ("first half", 0, SLAB_SIZE / 2),
            ("second half", SLAB_SIZE / 2, SLAB_SIZE / 2),
            ("first 30 bytes", 0, 30),
            ("middle 30 bytes", SLAB_SIZE / 2 - 15, 30),
            ("last 30 bytes", SLAB_SIZE - 30, 30),
            ("first 4KiB", 0, 4096),
            ("middle 4KiB", SLAB_SIZE / 2 - 2048, 4096),
            ("last 4KiB", SLAB_SIZE - 4096, 4096),
        ];

        for (name, offset, length) in test_cases {
            let mut slab = slabs[0].clone();
            slab.offset = offset as u32;
            slab.length = length as u32;

            let mut recovered_data = Vec::with_capacity(length);
            SlabRecovery::new(hosts.clone(), app_key.clone(), slab)
                .recover_shards()
                .await
                .unwrap()
                .decode()
                .await
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
}
