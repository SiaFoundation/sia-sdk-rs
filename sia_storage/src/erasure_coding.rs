use std::mem;

use bytes::{Bytes, BytesMut};
use reed_solomon_erasure::galois_8::ReedSolomon;
use sia_core::rhp4::{SECTOR_SIZE, SEGMENT_SIZE};
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

pub(crate) struct ErasureCoder {
    encoder: ReedSolomon,
}

impl ErasureCoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        Ok(ErasureCoder {
            encoder: ReedSolomon::new(data_shards, parity_shards)?,
        })
    }

    pub fn data_shards(&self) -> usize {
        self.encoder.data_shard_count()
    }

    /// encodes the shards using reed solomon erasure coding,
    /// computing the parity shards and overwriting their values.
    pub fn encode_shards(&self, shards: &mut [BytesMut]) -> Result<()> {
        self.encoder.encode(shards)?;
        Ok(())
    }

    /// reconstructs the missing datashards from the available ones.
    pub fn reconstruct_data_shards(&self, shards: &mut [Option<BytesMut>]) -> Result<()> {
        self.encoder.reconstruct_data(shards)?;
        Ok(())
    }

    /// write_data_shards writes up to 'n' bytes from the given reconstructed shards
    /// to the provided writer, skipping the first `skip` bytes.
    pub async fn write_data_shards<W: AsyncWrite + Unpin>(
        w: &mut W,
        shards: &[Bytes],
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

                let start = offset + skip;
                let length = n.min(SEGMENT_SIZE - skip);

                w.write_all(&shard[start..start + length]).await?;
                n -= length;
                skip = 0;
            }
            offset += SEGMENT_SIZE;
        }
        Ok(())
    }
}

/// A streaming reader that interleaves incoming bytes across a slab's data
/// shards as they become available. Yields a [ReadSlab] whenever a full slab
/// has been accumulated; call [SlabReader::finish] to recover any trailing
/// partial slab.
pub(crate) struct SlabReader {
    data_shards: usize,
    shards: Vec<BytesMut>,
    length: usize,
}

pub(crate) struct ReadSlab {
    pub length: usize,
    pub shards: Vec<BytesMut>,
}

impl SlabReader {
    pub(crate) fn new(data_shards: usize, parity_shards: usize) -> Self {
        let total_shards = data_shards + parity_shards;
        Self {
            data_shards,
            shards: vec![BytesMut::zeroed(SECTOR_SIZE); total_shards],
            length: 0,
        }
    }

    pub fn length(&self) -> usize {
        self.length
    }

    pub fn slab_size(&self) -> usize {
        self.data_shards * SECTOR_SIZE
    }

    /// Finalizes the slab reader, returning any remaining data as a slab.
    pub(crate) fn finish(mut self) -> Option<ReadSlab> {
        if self.length == 0 {
            return None;
        }
        let length = self.length;
        let shards = mem::take(&mut self.shards);
        Some(ReadSlab { length, shards })
    }

    /// Reads data from the reader until reaching the optimal slab size or EOF,
    /// whichever comes first. This should be called in a loop until EOF is
    /// reached.
    ///
    /// If the optimal slab size is reached, the completed slab is returned.
    /// Any remaining data should be retrieved using [finish](Self::finish).
    pub(crate) async fn read_slab<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
    ) -> io::Result<(usize, Option<ReadSlab>)> {
        let remaining = self.slab_size() - self.length;
        if remaining == 0 {
            return Ok((0, None));
        }
        let mut r = r.take(remaining as u64);
        let mut total_read = 0;
        loop {
            if self.length == self.slab_size() {
                break;
            }

            // calculate current position in the interleaved layout
            let stripe_size = SEGMENT_SIZE * self.data_shards;
            let shard_index = (self.length % stripe_size) / SEGMENT_SIZE;
            let byte_in_seg = self.length % SEGMENT_SIZE;
            let seg_start = (self.length / stripe_size) * SEGMENT_SIZE;

            let segment =
                &mut self.shards[shard_index][seg_start + byte_in_seg..seg_start + SEGMENT_SIZE];
            let n = r.read(segment).await?;
            if n == 0 {
                break;
            }
            self.length += n;
            total_read += n;
        }
        let slab = if self.length == self.slab_size() {
            let length = mem::take(&mut self.length);
            let total_shards = self.shards.len();
            let shards = mem::replace(
                &mut self.shards,
                vec![BytesMut::zeroed(SECTOR_SIZE); total_shards],
            );
            Some(ReadSlab { length, shards })
        } else {
            None
        };
        Ok((total_read, slab))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn init_shard(i: u8) -> BytesMut {
        let mut buf = BytesMut::with_capacity(SECTOR_SIZE);
        buf.resize(SECTOR_SIZE, i);
        buf
    }

    cross_target_tests! {
    async fn test_encode_shards() {
        let data_shards = 2;
        let parity_shards = 3;
        let coder = ErasureCoder::new(data_shards, parity_shards).unwrap();

        let mut shards: Vec<BytesMut> = [
            init_shard(1),
            init_shard(2),
            init_shard(0),
            init_shard(0),
            init_shard(0),
        ]
        .into();

        coder.encode_shards(&mut shards).unwrap();

        let expected_shards: Vec<BytesMut> = vec![
            init_shard(1),
            init_shard(2),
            init_shard(7),  // parity shard 1
            init_shard(4),  // parity shard 2
            init_shard(13), // parity shard 3
        ];
        assert_eq!(shards, expected_shards);

        // reconstruct data shards
        for i in 0..data_shards {
            let mut shards: Vec<Option<BytesMut>> = shards.iter().cloned().map(Some).collect();
            shards[i] = None;
            coder.reconstruct_data_shards(&mut shards).unwrap();
            let shards: Vec<BytesMut> = shards.into_iter().map(|s| s.unwrap()).collect();
            assert_eq!(shards, expected_shards);
        }
    }

    async fn test_striped_read() {
        const DATA_SHARDS: usize = 3;
        const PARITY_SHARDS: usize = 2;
        const SLAB_SIZE: usize = SECTOR_SIZE * DATA_SHARDS;

        let test_cases = vec![
            // (data size, expected size)
            (100, 100),               // under
            (SLAB_SIZE, SLAB_SIZE),   // exact
            (2 * SLAB_SIZE, SLAB_SIZE), // over
        ];

        for (data_size, expected_size) in test_cases {
            let mut data = vec![0u8; data_size];
            getrandom::fill(&mut data).unwrap();

            let mut reader = SlabReader::new(DATA_SHARDS, PARITY_SHARDS);
            let (n, slab) = reader
                .read_slab(&mut Cursor::new(data.clone()))
                .await
                .unwrap();
            assert_eq!(n, expected_size, "data size {data_size} read mismatch");

            let (size, shards) = if data_size >= SLAB_SIZE {
                let slab = slab.expect("expected full slab");
                (slab.length, slab.shards)
            } else {
                assert!(slab.is_none(), "data size {data_size} should not fill a slab");
                let slab = reader.finish().unwrap();
                (slab.length, slab.shards)
            };

            assert_eq!(size, expected_size, "data size {data_size} mismatch");
            assert_eq!(
                shards.len(),
                DATA_SHARDS + PARITY_SHARDS,
                "data size {data_size} shard count mismatch"
            );

            for (i, data) in data[..size].chunks(64).enumerate() {
                let mut chunk = [0u8; SEGMENT_SIZE];
                chunk[..data.len()].copy_from_slice(data); // pad it out with zeros
                let index = i % DATA_SHARDS;
                let offset = (i / DATA_SHARDS) * SEGMENT_SIZE;

                assert_eq!(
                    &shards[index][offset..offset + 64],
                    chunk,
                    "data size {data_size} shard {index} mismatch at offset {offset}"
                );
            }
        }
    }

    async fn test_striped_read_write() {
        const DATA_SHARDS: usize = 4;
        const PARITY_SHARDS: usize = 1;
        let coder = ErasureCoder::new(DATA_SHARDS, PARITY_SHARDS).unwrap();

        let mut data = BytesMut::zeroed(SECTOR_SIZE * 7 / 2); // 3.5 shards of data
        data[..SECTOR_SIZE].fill(1);
        data[SECTOR_SIZE..2 * SECTOR_SIZE].fill(2);
        data[2 * SECTOR_SIZE..3 * SECTOR_SIZE].fill(3);
        data[3 * SECTOR_SIZE..].fill(4);
        let data = data.freeze();

        let mut reader = SlabReader::new(DATA_SHARDS, PARITY_SHARDS);
        let (n, slab) = reader
            .read_slab(&mut Cursor::new(data.clone()))
            .await
            .unwrap();
        assert_eq!(n, data.len());
        assert!(slab.is_none()); // 3.5 shards doesn't fill a 4-shard slab
        let slab = reader.finish().unwrap();
        let size = slab.length;
        let mut shards = slab.shards;
        assert_eq!(size, data.len());

        // we expect 5 shards and the last one is an empty parity shard
        assert_eq!(shards.len(), 5);
        assert_eq!(size as usize, SECTOR_SIZE * 7 / 2);
        assert_eq!(shards[4], BytesMut::zeroed(SECTOR_SIZE)); // parity shard should be empty

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
        assert_ne!(shards[4], BytesMut::zeroed(SECTOR_SIZE));

        // joining the shards back together should result in the original data
        let shards: Vec<Bytes> = shards.iter().cloned().map(|s| s.freeze()).collect();
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
    }
}
