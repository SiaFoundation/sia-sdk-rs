use crate::rhp::{SECTOR_SIZE, SEGMENT_SIZE};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::io::{self, Read};
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

pub struct Encoder {
    encoder: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
}

impl Encoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        Ok(Encoder {
            encoder: ReedSolomon::new(data_shards, parity_shards).unwrap(),
            data_shards,
            parity_shards,
        })
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

        let mut buf = Vec::with_capacity(SEGMENT_SIZE);
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
                buf.clear(); // clear buffer for next read
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_shards() {
        let data_shards = 2;
        let parity_shards = 3;
        let mut encoder = Encoder::new(data_shards, parity_shards).unwrap();

        let mut shards: Vec<Vec<u8>> = [
            vec![1u8; SECTOR_SIZE],
            vec![2u8; SECTOR_SIZE],
            vec![0u8; SECTOR_SIZE],
            vec![0u8; SECTOR_SIZE],
            vec![0u8; SECTOR_SIZE],
        ]
        .into();

        encoder.encode_shards(&mut shards).unwrap();

        assert_eq!(shards[0], vec![1u8; SECTOR_SIZE]);
        assert_eq!(shards[1], vec![2u8; SECTOR_SIZE]);
        assert_eq!(shards[2], vec![7u8; SECTOR_SIZE]);
        assert_eq!(shards[3], vec![4u8; SECTOR_SIZE]);
        assert_eq!(shards[4], vec![13u8; SECTOR_SIZE]);
    }
}
