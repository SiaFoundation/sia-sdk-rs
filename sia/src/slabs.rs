use futures::StreamExt;
use futures::future::try_join_all;
use futures::stream::FuturesUnordered;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::encoding::SiaEncodable;
use crate::encryption::{encrypt_shard, encrypt_shards};
use crate::erasure_coding::{self, ErasureCoder};
use crate::rhp::{Error as RHPError, SECTOR_SIZE};
use crate::signing::PublicKey;
use crate::types::Hash256;

pub trait SectorUploader {
    fn write_sector(
        &self,
        sector: impl AsRef<[u8]>,
    ) -> impl Future<Output = Result<Sector, RHPError>>;
}

pub trait SectorDownloader {
    fn read_sector(
        &self,
        host: &PublicKey,
        root: &Hash256,
        limit: usize,
        offset: usize,
    ) -> impl Future<Output = Result<Vec<u8>, RHPError>>;
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("rhp error: {0}")]
    RHPError(#[from] RHPError),
    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("encoder error: {0}")]
    EncoderError(#[from] erasure_coding::Error),
    #[error("not enough shards: {0}/{1}")]
    NotEnoughShards(u8, u8),
}

/// A Sector is a unit of data stored on the Sia network. It can be referenced by its Merkle root.
pub struct Sector {
    pub root: Hash256,
    pub host_key: PublicKey,
}

/// A Slab is an erasure-coded collection of sectors. The sectors can be downloaded and
/// used to recover the original data.
pub struct Slab {
    pub encryption_key: [u8; 32],
    pub min_shards: u8,
    pub sectors: Vec<Sector>,
}

impl Slab {
    /// creates a unique identifier for the resulting slab to be referenced by hashing
    /// its contents, excluding the host key.
    pub fn digest(&self) -> Hash256 {
        let mut state = blake2b_simd::Params::new().hash_length(32).to_state();

        (self.min_shards as u64).encode(&mut state).unwrap();
        self.encryption_key.encode(&mut state).unwrap();
        self.sectors.iter().for_each(|sector| {
            sector.root.encode(&mut state).unwrap();
        });
        state.finalize().into()
    }

    /// Reads a single slab from the provided reader, erasure codes it, then uploads the resulting sectors.
    pub async fn upload_slab<R: AsyncReadExt + Unpin, S: SectorUploader>(
        r: &mut R,
        uploader: S,
        encryption_key: [u8; 32],
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Self, Error> {
        let mut rs = ErasureCoder::new(data_shards as usize, parity_shards as usize)?;
        let mut shards = rs.read_encoded_shards(r).await?;
        encrypt_shards(&encryption_key, &mut shards, 0);

        let mut futures = Vec::new();
        for shard in shards {
            futures.push(uploader.write_sector(shard));
        }

        let results = try_join_all(futures).await?;
        Ok(Slab {
            encryption_key,
            min_shards: data_shards,
            sectors: results,
        })
    }

    /// Downloads a slab from the provided hosts. If enough shards are recovered,
    /// the reconstructed data will be written to the provided writer.
    pub async fn download_slab<W: AsyncWriteExt + Unpin, S: SectorDownloader>(
        &self,
        writer: &mut W,
        downloader: &S,
        offset: usize,
        length: usize,
    ) -> Result<(), Error> {
        let mut sector_futures = FuturesUnordered::new();
        for (i, sector) in self.sectors.iter().enumerate() {
            sector_futures.push(async move {
                downloader
                    .read_sector(&sector.host_key, &sector.root, SECTOR_SIZE, 0)
                    .await
                    .map(|data| (i, data))
            });
        }
        let mut rs = ErasureCoder::new(
            self.min_shards as usize,
            self.sectors.len() - self.min_shards as usize,
        )?;
        let mut successful_shards: Vec<Option<Vec<u8>>> = vec![None; self.sectors.len()];

        let mut successful: u8 = 0;
        while let Some(result) = sector_futures.next().await {
            match result {
                Ok((index, mut data)) => {
                    successful += 1;
                    encrypt_shard(&self.encryption_key, &mut data, index as u8, 0);
                    successful_shards[index] = Some(data);

                    if successful == self.min_shards {
                        break;
                    }
                }
                Err(_) => {
                    // ignore failures until after all shards are attempted
                    // TODO: log
                }
            }
        }

        if successful < self.min_shards {
            return Err(Error::NotEnoughShards(successful, self.min_shards));
        }

        rs.write_reconstructed_shards(writer, &mut successful_shards, offset, length)
            .await?;
        Ok(())
    }
}
