use futures::StreamExt;
use futures::future::try_join_all;
use futures::stream::FuturesUnordered;
use serde::{Deserialize, Serialize};
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
        offset: usize,
        limit: usize,
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
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
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
    pub offset: usize,
    pub length: usize,
}

impl Slab {
    /// creates a unique identifier for the resulting slab to be referenced by hashing
    /// its contents, excluding the host key, length, and offset.
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
    pub async fn upload<R: AsyncReadExt + Unpin, S: SectorUploader>(
        r: &mut R,
        uploader: &S,
        encryption_key: [u8; 32],
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Self, Error> {
        let mut rs = ErasureCoder::new(data_shards as usize, parity_shards as usize)?;
        let (mut shards, length) = rs.read_encoded_shards(r).await?;
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
            offset: 0,
            length,
        })
    }

    /// Downloads a slab from the provided hosts. If enough shards are recovered,
    /// the reconstructed data will be written to the provided writer.
    pub async fn download<W: AsyncWriteExt + Unpin, S: SectorDownloader>(
        &self,
        writer: &mut W,
        downloader: &S,
    ) -> Result<(), Error> {
        let mut sector_futures = FuturesUnordered::new();
        for (i, sector) in self.sectors.iter().enumerate() {
            sector_futures.push(async move {
                downloader
                    .read_sector(&sector.host_key, &sector.root, 0, SECTOR_SIZE)
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

        rs.write_reconstructed_shards(writer, &mut successful_shards, self.offset, self.length)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hash_256;
    use crate::rhp::sector_root;
    use rand::RngCore;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    struct MockUploadDownloader {
        sectors: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl SectorDownloader for MockUploadDownloader {
        async fn read_sector(
            &self,
            _: &PublicKey,
            root: &Hash256,
            offset: usize,
            limit: usize,
        ) -> Result<Vec<u8>, RHPError> {
            let sectors = self.sectors.lock().await;
            match sectors.get(&root.to_string()) {
                Some(data) => Ok(data[offset..offset + limit].to_vec()),
                None => Err(RHPError::Transport("sector not found".into())),
            }
        }
    }

    impl SectorUploader for MockUploadDownloader {
        async fn write_sector(&self, sector: impl AsRef<[u8]>) -> Result<Sector, RHPError> {
            let root = sector_root(sector.as_ref());
            let sector_data = sector.as_ref().to_vec();
            let mut sectors = self.sectors.lock().await;
            sectors.insert(root.to_string(), sector_data);

            Ok(Sector {
                root,
                host_key: PublicKey::new(rand::random()),
            })
        }
    }

    #[tokio::test]
    async fn test_slab_roundtrip() {
        let mock = MockUploadDownloader {
            sectors: Mutex::new(HashMap::new()),
        };

        let mut data = vec![0u8; 3 * SECTOR_SIZE];
        rand::rng().fill_bytes(&mut data);

        let key: [u8; 32] = rand::random();
        let slab: Slab = Slab::upload(&mut data.as_ref(), &mock, key, 3, 2)
            .await
            .unwrap();
        assert_eq!(slab.min_shards, 3);
        assert_eq!(slab.sectors.len(), 5);

        let mut writer: Vec<u8> = Vec::new();
        slab.download(&mut writer, &mock).await.unwrap();

        assert_eq!(writer, data);
    }

    #[tokio::test]
    async fn test_partial_slab_roundtrip() {
        let mock = MockUploadDownloader {
            sectors: Mutex::new(HashMap::new()),
        };

        let mut data = vec![0u8; 1024];
        rand::rng().fill_bytes(&mut data);

        let key: [u8; 32] = rand::random();
        let slab: Slab = Slab::upload(&mut data.as_ref(), &mock, key, 3, 2)
            .await
            .unwrap();
        assert_eq!(slab.min_shards, 3);
        assert_eq!(slab.sectors.len(), 5);

        let mut writer: Vec<u8> = Vec::new();
        slab.download(&mut writer, &mock).await.unwrap();

        assert_eq!(writer, data);
    }

    /// tests Slab.digest against a reference digest
    #[test]
    fn test_slab_digest() {
        let s = Slab {
            min_shards: 1,
            encryption_key: [
                152, 138, 169, 77, 22, 195, 154, 192, 91, 139, 241, 61, 75, 225, 38, 124, 225, 31,
                187, 165, 80, 215, 75, 121, 115, 204, 235, 9, 90, 248, 68, 92,
            ],
            sectors: vec![
                Sector {
                    root: hash_256!(
                        "fb0a42cce246d6bb9716eb0e97579a1d0d5c2bb34d7234e9ae271d4fd8201b24"
                    ),
                    host_key: PublicKey::new(rand::random()), // host key is not included in the digest
                },
                Sector {
                    root: hash_256!(
                        "8125994daee38e1fbaf7a26c7935420ce055202f7175eae98d291ebe80f2b00e"
                    ),
                    host_key: PublicKey::new(rand::random()), // host key is not included in the digest
                },
                Sector {
                    root: hash_256!(
                        "54ee41b57b9439868b119b8fe1c6c602bd6b35e27d31400c5bb85912b60c9f0a"
                    ),
                    host_key: PublicKey::new(rand::random()), // host key is not included in the digest
                },
            ],
            // length and offset are not included in the digest
            length: 100,
            offset: 100,
        };

        assert_eq!(
            s.digest().to_string(),
            "d1aea84f8682d7ae17b6c1f14dc344eb70b9328ee913a76fc241559657b06284"
        )
    }
}
