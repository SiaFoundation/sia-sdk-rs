use crate::rhp::{SECTOR_SIZE, SEGMENT_SIZE};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::io::{self, BufReader, Read};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ReedSolomon error: {0}")]
    ReedSolomon(#[from] reed_solomon_erasure::Error),

    #[error("Invalid number of shards: expected {expected}, got {actual}")]
    InvalidNumberOfShards { expected: usize, actual: usize },

    #[error("Invalid shard size: expected {expected}, got {actual}")]
    InvalidShardSize { expected: usize, actual: usize },

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
            encoder: ReedSolomon::new(data_shards, parity_shards).unwrap(),
            data_shards,
            parity_shards,
        })
    }

    /// read_encoded_shards is a convenience method that reads data from the
    /// given reader and returns erasure coded shards in a single call.
    pub fn read_encoded_shards<R: io::Read>(&mut self, r: &mut R) -> Result<Vec<Vec<u8>>> {
        // use a buffered reader since striped_read will read 64 bytes at a time
        let mut shards = self.striped_read(&mut BufReader::new(r))?;
        self.encode_shards(&mut shards)?;
        Ok(shards)
    }

    /// striped_read reads data from the given reader into a vector of shards.
    pub fn striped_read<R: io::Read>(&self, r: &mut R) -> Result<Vec<Vec<u8>>> {
        // allocate memory for shards
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(self.data_shards + self.parity_shards);
        for _ in 0..self.data_shards + self.parity_shards {
            shards.push(vec![0u8; SECTOR_SIZE]);
        }

        // limit total read size to the size of the slab
        let mut r = r.take((self.data_shards + self.parity_shards) as u64 * SECTOR_SIZE as u64);

        let mut buf = [0u8; SEGMENT_SIZE];
        for off in (0..).map(|n| n * SEGMENT_SIZE) {
            for shard in shards.iter_mut() {
                match r.read_exact(&mut buf) {
                    Ok(_) => {}
                    Err(err) => {
                        if err.kind() == io::ErrorKind::UnexpectedEof {
                            // EOF reached, the remaining bytes are zeros
                            shard[off..off + SEGMENT_SIZE].copy_from_slice(&buf);
                            return Ok(shards);
                        } else {
                            // Some other IO error
                            return Err(Error::Io(err));
                        }
                    }
                };
                shard[off..off + SEGMENT_SIZE].copy_from_slice(&buf);
                buf.fill(0); // clear buffer
            }
        }
        Ok(shards)
    }

    /// encode_shards encodes the shards using reed solomon erasure coding,
    /// computing the parity shards and overwriting their values.
    pub fn encode_shards(&mut self, shards: &mut [Vec<u8>]) -> Result<()> {
        self.encoder.encode(shards)?;
        Ok(())
    }

    /// reconstruct reconstructs the missing shards from the available ones.
    pub fn reconstruct(&mut self, shards: &mut [Option<Vec<u8>>]) -> Result<()> {
        self.encoder.reconstruct(shards)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_shards() {
        let data_shards = 2;
        let parity_shards = 3;
        let mut coder = ErasureCoder::new(data_shards, parity_shards).unwrap();

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
    }

    #[test]
    fn test_striped_read() {
        let coder = ErasureCoder::new(3, 1).unwrap();

        let mut data = vec![0u8; SECTOR_SIZE * 7 / 2]; // 3.5 shards of data
        data[..SECTOR_SIZE].fill(1);
        data[SECTOR_SIZE..2 * SECTOR_SIZE].fill(2);
        data[2 * SECTOR_SIZE..3 * SECTOR_SIZE].fill(3);
        data[3 * SECTOR_SIZE..].fill(4);

        let shards = coder.striped_read(&mut data.as_slice()).unwrap();
        assert_eq!(shards.len(), 4);

        for shard in shards {
            // every shard should be of SECTOR_SIZE
            assert_eq!(shard.len(), SECTOR_SIZE);

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

            // half of the fourth quarter is 4s
            assert_eq!(
                shard[SECTOR_SIZE / 4 * 3..SECTOR_SIZE / 8 * 7],
                [4u8; SECTOR_SIZE / 8]
            );

            // remainder is padded with 0s
            assert_eq!(shard[SECTOR_SIZE / 8 * 7..], [0u8; SECTOR_SIZE / 8]);
        }
    }
}
