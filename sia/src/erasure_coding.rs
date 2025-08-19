use crate::rhp::{SECTOR_SIZE, SEGMENT_SIZE};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::io::{self, BufReader, BufWriter, Read, Write};
use thiserror::Error;

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
    #[allow(dead_code)]
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        Ok(ErasureCoder {
            encoder: ReedSolomon::new(data_shards, parity_shards)?,
            data_shards,
            parity_shards,
        })
    }

    /// read_encoded_shards is a convenience method that reads data from the
    /// given reader and returns erasure coded shards in a single call.
    #[allow(dead_code)]
    pub fn read_encoded_shards<R: io::Read>(&mut self, r: &mut R) -> Result<Vec<Vec<u8>>> {
        // use a buffered reader since striped_read will read 64 bytes at a time
        let mut shards = self.striped_read(&mut BufReader::new(r))?;
        self.encode_shards(&mut shards)?;
        Ok(shards)
    }

    /// write_reconstructed_shards is a convenience method that attempts to
    /// recover the data shards of the provided shards, join them and write the
    /// result to the provided writer. It skips the first `skip` bytes and
    /// writes 'n' bytes in total.
    #[allow(dead_code)]
    pub fn write_reconstructed_shards<W: io::Write>(
        &mut self,
        w: &mut W,
        shards: &mut [Option<Vec<u8>>],
        skip: usize,
        n: usize,
    ) -> Result<()> {
        // reconstruct just the data, that's all we need
        self.reconstruct_data(shards)?;

        // use a buffered writer since striped_write will write 64 bytes at a time
        let mut w = BufWriter::new(w);
        self.striped_write(&mut w, shards, skip, n)?;
        w.flush()?;
        Ok(())
    }

    /// encode_shards encodes the shards using reed solomon erasure coding,
    /// computing the parity shards and overwriting their values.
    fn encode_shards(&mut self, shards: &mut [Vec<u8>]) -> Result<()> {
        self.encoder.encode(shards)?;
        Ok(())
    }

    /// reconstruct reconstructs the missing shards from the available ones.
    #[allow(dead_code)]
    fn reconstruct(&mut self, shards: &mut [Option<Vec<u8>>]) -> Result<()> {
        self.encoder.reconstruct(shards)?;
        Ok(())
    }

    /// reconstruct reconstructs the missing datashards from the available ones.
    fn reconstruct_data(&mut self, shards: &mut [Option<Vec<u8>>]) -> Result<()> {
        self.encoder.reconstruct_data(shards)?;
        Ok(())
    }

    /// striped_write writes up to 'n' bytes from the given reconstructed shards
    /// to the provided writer, skipping the first `skip` bytes.
    fn striped_write<W: io::Write>(
        &self,
        w: &mut W,
        shards: &[Option<Vec<u8>>],
        skip: usize,
        n: usize,
    ) -> Result<()> {
        let mut skip = skip;
        let mut n = n;

        for off in (0..).map(|n| n * SEGMENT_SIZE) {
            if n == 0 {
                return Ok(()); // done
            }

            for shard in &shards[..self.data_shards] {
                let mut segment = match shard {
                    Some(s) => &s[off..off + SEGMENT_SIZE],
                    None => {
                        return Err(Error::ReedSolomon(
                            reed_solomon_erasure::Error::TooFewDataShards,
                        ))
                    }
                };

                if skip > segment.len() {
                    skip -= segment.len();
                    continue;
                } else if skip > 0 {
                    segment = &segment[skip..];
                    skip = 0;
                }
                if n < segment.len() {
                    segment = &segment[..n];
                }
                w.write_all(segment)?;
                n -= segment.len();
            }
        }
        Ok(())
    }

    /// striped_read reads data from the given reader into a vector of shards.
    fn striped_read<R: io::Read>(&self, r: &mut R) -> Result<Vec<Vec<u8>>> {
        // allocate memory for shards
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(self.data_shards);
        for _ in 0..self.data_shards + self.parity_shards {
            shards.push(vec![0u8; SECTOR_SIZE]);
        }

        // limit total read size to the size of the slab's data shards
        let mut r = r.take(self.data_shards as u64 * SECTOR_SIZE as u64);

        let mut buf = [0u8; SEGMENT_SIZE];
        for off in (0..).map(|n| n * SEGMENT_SIZE) {
            for shard in shards[..self.data_shards].iter_mut() {
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

        // reconstruct data shards
        for i in 0..data_shards {
            let mut shards: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
            shards[i] = None;
            coder.reconstruct_data(&mut shards).unwrap();
            let shards: Vec<Vec<u8>> = shards.into_iter().map(|s| s.unwrap()).collect();
            assert_eq!(shards, expected_shards);
        }
    }

    #[test]
    fn test_striped_read_write() {
        let mut coder = ErasureCoder::new(4, 1).unwrap();

        let mut data = vec![0u8; SECTOR_SIZE * 7 / 2]; // 3.5 shards of data
        data[..SECTOR_SIZE].fill(1);
        data[SECTOR_SIZE..2 * SECTOR_SIZE].fill(2);
        data[2 * SECTOR_SIZE..3 * SECTOR_SIZE].fill(3);
        data[3 * SECTOR_SIZE..].fill(4);

        let mut shards = coder.striped_read(&mut data.as_slice()).unwrap();

        // we expect 5 shards and the last one is an empty parity shard
        assert_eq!(shards.len(), 5);
        assert_eq!(shards[4], [0u8; SECTOR_SIZE]);

        for shard in &shards[..4] {
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

        // encoding the read shards should succeed without errors and cause the
        // parity shard to be filled
        coder.encode_shards(&mut shards).unwrap();
        assert_ne!(shards[4], [0u8; SECTOR_SIZE]);

        // joining the shards back together should result in the original data
        let shards: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
        let mut joined_data = Vec::new();
        coder
            .striped_write(&mut joined_data, &shards, 0, data.len())
            .unwrap();
        assert_eq!(joined_data, data);

        // join only the first half
        let mut joined_data = Vec::new();
        coder
            .striped_write(&mut joined_data, &shards, 0, data.len() / 2)
            .unwrap();
        assert_eq!(joined_data, data[..data.len() / 2]);

        // join only the second half
        let mut joined_data = Vec::new();
        coder
            .striped_write(&mut joined_data, &shards, data.len() / 2, data.len() / 2)
            .unwrap();
        assert_eq!(joined_data, data[data.len() / 2..]);
    }

    #[test]
    fn test_read_encoded_write_reconstructed() {
        let mut coder = ErasureCoder::new(4, 1).unwrap();
        let mut data = vec![0u8; SECTOR_SIZE * 7 / 2]; // 3.5 shards of data
        data[..SECTOR_SIZE].fill(1);
        data[SECTOR_SIZE..2 * SECTOR_SIZE].fill(2);
        data[2 * SECTOR_SIZE..3 * SECTOR_SIZE].fill(3);
        data[3 * SECTOR_SIZE..].fill(4);

        // encode the data
        let encoded_shards = coder.read_encoded_shards(&mut &data[..]).unwrap();

        // drop a shard
        let mut encoded_shards = encoded_shards.into_iter().map(Some).collect::<Vec<_>>();
        encoded_shards[2] = None; // drop the third shard

        // reconstruct the data shards
        let mut reconstructed_data: Vec<u8> = Vec::new();
        coder
            .write_reconstructed_shards(&mut reconstructed_data, &mut encoded_shards, 0, data.len())
            .unwrap();
        assert_eq!(data, reconstructed_data);
    }
}
