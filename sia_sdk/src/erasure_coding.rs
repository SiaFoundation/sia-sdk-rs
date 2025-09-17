use crate::rhp::{SECTOR_SIZE, SEGMENT_SIZE};
use reed_solomon_erasure::galois_8::ReedSolomon;
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Error)]
pub enum Error {
    #[error("ReedSolomon error: {0}")]
    ReedSolomon(#[from] reed_solomon_erasure::Error),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct ErasureCoder {
    encoder: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
}

impl ErasureCoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        Ok(ErasureCoder {
            encoder: ReedSolomon::new(data_shards, parity_shards)?,
            data_shards,
            parity_shards,
        })
    }

    /// encodes the shards using reed solomon erasure coding,
    /// computing the parity shards and overwriting their values.
    pub fn encode_shards(&self, shards: &mut [Vec<u8>]) -> Result<()> {
        self.encoder.encode(shards)?;
        Ok(())
    }

    /// reconstructs the missing shards from the available ones.
    pub fn reconstruct(&self, shards: &mut [Option<Vec<u8>>]) -> Result<()> {
        self.encoder.reconstruct(shards)?;
        Ok(())
    }

    /// reconstructs the missing datashards from the available ones.
    pub fn reconstruct_data_shards(&self, shards: &mut [Option<Vec<u8>>]) -> Result<()> {
        self.encoder.reconstruct_data(shards)?;
        Ok(())
    }

    /// write_data_shards writes up to 'n' bytes from the given reconstructed shards
    /// to the provided writer, skipping the first `skip` bytes.
    pub async fn write_data_shards<W: AsyncWrite + Unpin>(
        w: &mut W,
        shards: &[Option<Vec<u8>>],
        mut skip: usize,
        mut n: usize,
    ) -> Result<()> {
        let row_bytes = shards.len() * SEGMENT_SIZE;
        let rows = skip / row_bytes;
        let mut offset = rows * SEGMENT_SIZE;
        skip %= row_bytes;
        while n > 0 {
            for shard in shards {
                if n == 0 {
                    return Ok(());
                } else if skip > SEGMENT_SIZE {
                    skip -= SEGMENT_SIZE;
                    continue;
                }

                let segment = shard.as_ref().ok_or(Error::ReedSolomon(
                    reed_solomon_erasure::Error::TooFewDataShards,
                ))?;

                let start = offset + skip;
                let length = n.min(SEGMENT_SIZE - skip);

                w.write_all(&segment[start..start + length]).await?;
                n -= length;
                skip = 0;
            }
            offset += SEGMENT_SIZE;
        }
        Ok(())
    }

    /// read_shards reads data from the given reader into a vector of shards.
    pub async fn read_shards<R: AsyncRead + Unpin>(
        &self,
        r: &mut R,
    ) -> Result<(Vec<Vec<u8>>, usize)> {
        // allocate memory for shards
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(self.data_shards);
        for _ in 0..self.data_shards + self.parity_shards {
            shards.push(Vec::with_capacity(SECTOR_SIZE));
        }

        // limit total read size to the size of the slab's data shards
        let mut r = r.take(self.data_shards as u64 * SECTOR_SIZE as u64);
        let mut data_size = 0;
        let mut segment = [0u8; SEGMENT_SIZE];
        let mut eof = false;
        for _ in (0..SECTOR_SIZE).step_by(SEGMENT_SIZE) {
            for shard in &mut shards[..self.data_shards].iter_mut() {
                let mut bytes_read = 0;
                while bytes_read < SEGMENT_SIZE {
                    // note: read_exact + UnexpectedEoF is not used due to the documentation
                    // saying "the contents of buf are unspecified." when UnexpectedEoF is
                    // returned. It's *most likely* fine to rely on the contents being
                    // a partial read, but better to not make the assumption for every
                    // possible implementation of the Read trait.
                    let n = r.read(&mut segment[bytes_read..]).await?;
                    if n == 0 {
                        eof = true;
                        break;
                    }
                    bytes_read += n;
                    data_size += n;
                }
                if bytes_read > 0 {
                    // the full segment is used regardless of bytes_read so
                    // that each shard is a multiple of SEGMENT_SIZE.
                    shard.extend_from_slice(&segment);
                }

                if eof {
                    break;
                }
            }
            if eof {
                break;
            }
        }
        // ensure all shards are the same length
        let shard_len = shards[0].len();
        for shard in &mut shards {
            shard.resize(shard_len, 0);
        }
        Ok((shards, data_size))
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::*;

    #[tokio::test]
    async fn test_encode_shards() {
        let data_shards = 2;
        let parity_shards = 3;
        let coder = ErasureCoder::new(data_shards, parity_shards).unwrap();

        let mut shards: Vec<Vec<u8>> = [
            vec![1u8; SECTOR_SIZE],
            vec![2u8; SECTOR_SIZE],
            vec![0u8; SECTOR_SIZE],
            vec![0u8; SECTOR_SIZE],
            vec![0u8; SECTOR_SIZE],
        ]
        .into();

        coder.encode_shards(&mut shards).unwrap();

        let expected_shards: Vec<Vec<u8>> = vec![
            vec![1u8; SECTOR_SIZE],
            vec![2u8; SECTOR_SIZE],
            vec![7u8; SECTOR_SIZE],  // parity shard 1
            vec![4u8; SECTOR_SIZE],  // parity shard 2
            vec![13u8; SECTOR_SIZE], // parity shard 3
        ];
        assert_eq!(shards, expected_shards);

        // reconstruct every shard
        for i in 0..shards.len() {
            let mut shards: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
            shards[i] = None;
            coder.reconstruct(&mut shards).unwrap();
            let shards: Vec<Vec<u8>> = shards.into_iter().map(|s| s.unwrap()).collect();
            assert_eq!(shards, expected_shards);
        }

        // reconstruct data shards
        for i in 0..data_shards {
            let mut shards: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
            shards[i] = None;
            coder.reconstruct_data_shards(&mut shards).unwrap();
            let shards: Vec<Vec<u8>> = shards.into_iter().map(|s| s.unwrap()).collect();
            assert_eq!(shards, expected_shards);
        }
    }

    #[tokio::test]
    async fn test_striped_read() {
        const DATA_SHARDS: usize = 3;
        const PARITY_SHARDS: usize = 2;

        let test_cases = vec![
            // (data size, expected size)
            (100, 100),                                                 // under
            (SECTOR_SIZE * DATA_SHARDS, SECTOR_SIZE * DATA_SHARDS),     // exact
            (2 * SECTOR_SIZE * DATA_SHARDS, SECTOR_SIZE * DATA_SHARDS), // over
        ];

        let coder = ErasureCoder::new(DATA_SHARDS, PARITY_SHARDS).unwrap();

        for (data_size, expected_size) in test_cases {
            let mut data = vec![0u8; data_size];
            rand::rng().fill_bytes(&mut data);

            let (shards, size) = coder.read_shards(&mut &data[..]).await.unwrap();

            assert_eq!(size, expected_size, "data size {data_size} mismatch");
            assert_eq!(
                shards.len(),
                DATA_SHARDS + PARITY_SHARDS,
                "data size {data_size} shard count mismatch"
            );

            for (i, data) in data[..size].chunks(64).enumerate() {
                let index = i % DATA_SHARDS;
                let offset = (i / DATA_SHARDS) * SEGMENT_SIZE;

                assert_eq!(
                    &shards[index][offset..offset + data.len()],
                    data,
                    "data size {data_size} shard {index} mismatch at offset {offset}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_striped_read_write() {
        const DATA_SHARDS: usize = 4;
        const PARITY_SHARDS: usize = 1;
        const DATA_SIZE: usize = SECTOR_SIZE * 7 / 2; // 3.5 shards of data
        const SHARD_SIZE: usize = DATA_SIZE.div_ceil(SEGMENT_SIZE) * SEGMENT_SIZE / DATA_SHARDS;
        let coder = ErasureCoder::new(DATA_SHARDS, PARITY_SHARDS).unwrap();

        let mut data = vec![0u8; DATA_SIZE];
        data[..SECTOR_SIZE].fill(1);
        data[SECTOR_SIZE..2 * SECTOR_SIZE].fill(2);
        data[2 * SECTOR_SIZE..3 * SECTOR_SIZE].fill(3);
        data[3 * SECTOR_SIZE..].fill(4);

        let (mut shards, size) = coder.read_shards(&mut data.as_slice()).await.unwrap();

        // we expect 5 shards and the last one is an empty parity shard
        assert_eq!(shards.len(), 5);
        assert_eq!(size, DATA_SIZE);
        assert_eq!(shards[4], [0u8; SHARD_SIZE]);

        for shard in &shards[..4] {
            assert_eq!(shard.len(), SHARD_SIZE);

            // first quarter of every shard is 1s
            assert_eq!(shard[0..SECTOR_SIZE / 4], [1u8; SECTOR_SIZE / 4]);

            // second quarter is 2s
            assert_eq!(
                shard[SECTOR_SIZE / 4..SECTOR_SIZE / 2],
                [2u8; SECTOR_SIZE / 4]
            );

            // third quarter is 3s
            assert_eq!(
                shard[SECTOR_SIZE / 2..SECTOR_SIZE / 4 * 3],
                [3u8; SECTOR_SIZE / 4]
            );

            // remainder is 4s
            assert_eq!(shard[SECTOR_SIZE / 4 * 3..], [4u8; SECTOR_SIZE / 8]);
        }

        // encoding the read shards should succeed without errors and cause the
        // parity shard to be filled
        coder.encode_shards(&mut shards).unwrap();
        assert_ne!(shards[4], [0u8; SHARD_SIZE]);

        // joining the shards back together should result in the original data
        let shards: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
        let mut joined_data = Vec::new();
        ErasureCoder::write_data_shards(&mut joined_data, &shards[..DATA_SHARDS], 0, data.len())
            .await
            .unwrap();
        assert_eq!(joined_data, data);

        // join only the first half
        let mut joined_data = Vec::new();
        ErasureCoder::write_data_shards(
            &mut joined_data,
            &shards[..DATA_SHARDS],
            0,
            data.len() / 2,
        )
        .await
        .unwrap();
        assert_eq!(joined_data, data[..data.len() / 2]);

        // join only the second half
        let mut joined_data = Vec::new();
        ErasureCoder::write_data_shards(
            &mut joined_data,
            &shards[..DATA_SHARDS],
            data.len() / 2,
            data.len() / 2,
        )
        .await
        .unwrap();
        assert_eq!(joined_data, data[data.len() / 2..]);
    }

    #[tokio::test]
    async fn test_read_encoded_write_reconstructed() {
        const DATA_SHARDS: usize = 4;
        const PARITY_SHARDS: usize = 1;
        let coder = ErasureCoder::new(DATA_SHARDS, PARITY_SHARDS).unwrap();
        let mut data = vec![0u8; SECTOR_SIZE * 7 / 2]; // 3.5 shards of data
        data[..SECTOR_SIZE].fill(1);
        data[SECTOR_SIZE..2 * SECTOR_SIZE].fill(2);
        data[2 * SECTOR_SIZE..3 * SECTOR_SIZE].fill(3);
        data[3 * SECTOR_SIZE..].fill(4);

        // encode the data
        let (mut shards, _) = coder.read_shards(&mut &data[..]).await.unwrap();
        coder.encode_shards(&mut shards).unwrap();

        // drop a shard
        let mut encoded_shards = shards.into_iter().map(Some).collect::<Vec<_>>();
        encoded_shards[2] = None; // drop the third shard

        // reconstruct the data shards
        let mut reconstructed_data: Vec<u8> = Vec::new();
        coder.reconstruct_data_shards(&mut encoded_shards).unwrap();
        ErasureCoder::write_data_shards(
            &mut reconstructed_data,
            &encoded_shards[..DATA_SHARDS],
            0,
            data.len(),
        )
        .await
        .unwrap();
        assert_eq!(data, reconstructed_data);
    }
}
