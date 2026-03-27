use async_stream::try_stream;
use bytes::{Bytes, BytesMut};
use futures::Stream;
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

    pub fn total_shards(&self) -> usize {
        self.encoder.total_shard_count()
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

pub(crate) async fn read_slab<R: AsyncRead + Unpin>(
    r: &mut R,
    data_shards: usize,
    parity_shards: usize,
) -> Result<(usize, Vec<BytesMut>)> {
    let total_shards = data_shards + parity_shards;
    let mut shards = vec![BytesMut::zeroed(SECTOR_SIZE); total_shards];
    // limit total read size to the size of the slab's data shards
    let mut r = r.take(data_shards as u64 * SECTOR_SIZE as u64);
    let mut data_size = 0;
    for off in (0..SECTOR_SIZE).step_by(SEGMENT_SIZE) {
        let start = off;
        let end = off + SEGMENT_SIZE;
        for shard in &mut shards[..data_shards].iter_mut() {
            let segment = &mut shard[start..end];
            let mut bytes_read = 0;
            while bytes_read < SEGMENT_SIZE {
                // note: read_exact + UnexpectedEoF is not used due to the documentation
                // saying "the contents of buf are unspecified." when UnexpectedEoF is
                // returned. It's *most likely* fine to rely on the contents being
                // a partial read, but better to not make the assumption for every
                // possible implementation of the Read trait.
                let n = r.read(&mut segment[bytes_read..]).await?;
                if n == 0 {
                    return Ok((data_size, shards));
                }
                bytes_read += n;
                data_size += n;
            }
        }
    }
    Ok((data_size, shards))
}

/// read_slabs reads slabs of data from the provided reader, returning the length of the data read and the corresponding shards for each slab. The slabs are read in a streaming fashion, so the caller can process
/// each slab as it is read without needing to load the entire data into memory at once.
pub(crate) fn read_slabs<R: AsyncRead + Unpin>(
    r: &mut R,
    data_shards: usize,
    parity_shards: usize,
) -> impl Stream<Item = Result<(usize, Vec<BytesMut>)>> {
    try_stream! {
        loop {
            let (data_size, shards) = read_slab(r, data_shards, parity_shards).await?;
            if data_size == 0 {
                break;
            }
            yield (data_size, shards);
        }
    }
}

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

    pub(crate) fn next_slab(&mut self) -> Option<ReadSlab> {
        if self.length != self.slab_size() {
            return None;
        }
        let length = std::mem::take(&mut self.length);
        let total_shards = self.shards.len();
        let shards = std::mem::replace(
            &mut self.shards,
            vec![BytesMut::zeroed(SECTOR_SIZE); total_shards],
        );
        self.length = 0;
        Some(ReadSlab { length, shards })
    }

    pub(crate) fn finish(mut self) -> Option<ReadSlab> {
        if self.length == 0 {
            return None;
        }
        let length = self.length;
        let shards = std::mem::take(&mut self.shards);
        Some(ReadSlab { length, shards })
    }

    /// Reads data from the reader until reaching the optimal slab size or EOF, whichever comes first.
    ///
    /// If there is still data in the reader, the resulting slab should be retrieved
    /// using [next_slab](Self::next_slab) before calling [read_slab](Self::read_slab) again.
    pub(crate) async fn read_slab<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> io::Result<usize> {
        let remaining = self.slab_size() - self.length;
        if remaining == 0 {
            return Ok(0);
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
        Ok(total_read)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use rand::Rng;

    use super::*;

    fn init_shard(i: u8) -> BytesMut {
        let mut buf = BytesMut::with_capacity(SECTOR_SIZE);
        buf.resize(SECTOR_SIZE, i);
        buf
    }

    #[tokio::test]
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

        for (data_size, expected_size) in test_cases {
            let mut data = vec![0u8; data_size];
            rand::rng().fill_bytes(&mut data);

            let (size, shards) =
                read_slab(&mut Cursor::new(data.clone()), DATA_SHARDS, PARITY_SHARDS)
                    .await
                    .unwrap();

            assert_eq!(
                size as usize, expected_size,
                "data size {data_size} mismatch"
            );
            assert_eq!(
                shards.len(),
                DATA_SHARDS + PARITY_SHARDS,
                "data size {data_size} shard count mismatch"
            );

            for (i, data) in data[..size as usize].chunks(64).enumerate() {
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

    #[tokio::test]
    async fn test_striped_read_write() {
        const DATA_SHARDS: usize = 4;
        const PARITY_SHARDS: usize = 1;
        let rs = ErasureCoder::new(DATA_SHARDS, PARITY_SHARDS).unwrap();

        let mut data = BytesMut::zeroed(SECTOR_SIZE * 7 / 2); // 3.5 shards of data
        data[..SECTOR_SIZE].fill(1);
        data[SECTOR_SIZE..2 * SECTOR_SIZE].fill(2);
        data[2 * SECTOR_SIZE..3 * SECTOR_SIZE].fill(3);
        data[3 * SECTOR_SIZE..].fill(4);
        let data = data.freeze();

        let (size, mut shards) =
            read_slab(&mut Cursor::new(data.clone()), DATA_SHARDS, PARITY_SHARDS)
                .await
                .unwrap();
        assert_eq!(size, data.len());

        // we expect 5 shards and the last one is an empty parity shard
        assert_eq!(shards.len(), 5);
        assert_eq!(size, SECTOR_SIZE * 7 / 2);
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
        rs.encode_shards(&mut shards).unwrap();
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

    const DATA_SHARDS: usize = 10;
    const PARITY_SHARDS: usize = 20;
    const SLAB_SIZE: usize = SECTOR_SIZE * DATA_SHARDS;

    fn assert_slab(data: &[u8], data_shards: usize, parity_shards: usize, slab: ReadSlab) {
        assert_eq!(slab.shards.len(), data_shards + parity_shards);
        assert_eq!(slab.length, data.len());
        for offset in (0..SLAB_SIZE).step_by(SEGMENT_SIZE) {
            let mut expected_segment = vec![0u8; SEGMENT_SIZE];
            if offset < data.len() {
                let n = SEGMENT_SIZE.min(data.len() - offset);
                expected_segment[..n].copy_from_slice(&data[offset..][..n]);
            }

            let shard_index = offset / SEGMENT_SIZE % data_shards;
            let segment_start = (offset / (SEGMENT_SIZE * data_shards)) * SEGMENT_SIZE;
            assert_eq!(
                &slab.shards[shard_index][segment_start..][..expected_segment.len()],
                expected_segment
            );
        }
    }

    #[tokio::test]
    async fn test_slab_reader_short() {
        let mut reader = SlabReader::new(DATA_SHARDS, PARITY_SHARDS);

        let data = b"Hello, world!";
        let mut cursor = Cursor::new(&data);
        let n = reader.read_slab(&mut cursor).await.unwrap();
        assert_eq!(n, data.len());
        assert_eq!(reader.length(), data.len());
        assert!(reader.next_slab().is_none());

        let n = reader.read_slab(&mut cursor).await.unwrap();
        assert_eq!(n, 0);

        let slab = reader.finish().unwrap();
        assert_eq!(slab.length, data.len());
        assert_eq!(slab.shards.len(), DATA_SHARDS + PARITY_SHARDS);
        assert_slab(data, DATA_SHARDS, PARITY_SHARDS, slab);
    }

    #[tokio::test]
    async fn test_slab_reader_unaligned() {
        let mut data = BytesMut::zeroed(SLAB_SIZE * 2 + 18);
        rand::rng().fill_bytes(&mut data);
        let data = data.freeze();

        let object_1 = &data[..SLAB_SIZE - 13];
        let object2 = &data[SLAB_SIZE - 13..];
        assert_eq!(object_1.len(), SLAB_SIZE - 13);
        assert_eq!(object2.len(), SLAB_SIZE + 13 + 18);
        let mut reader = SlabReader::new(DATA_SHARDS, PARITY_SHARDS);

        let mut cursor = Cursor::new(&object_1);
        let n = reader.read_slab(&mut cursor).await.unwrap();
        assert_eq!(n, object_1.len());
        assert_eq!(reader.length(), object_1.len());
        assert!(reader.next_slab().is_none());
        // object 1 should be fully read
        assert_eq!(reader.read_slab(&mut cursor).await.unwrap(), 0);

        let mut cursor = Cursor::new(&object2);
        let n = reader.read_slab(&mut cursor).await.unwrap();
        assert_eq!(n, 13); // only enough to fill the slab
        assert_eq!(reader.length(), SLAB_SIZE);
        let slab = reader.next_slab().unwrap();
        assert_slab(&data[..SLAB_SIZE], DATA_SHARDS, PARITY_SHARDS, slab);

        let n = reader.read_slab(&mut cursor).await.unwrap();
        assert_eq!(n, SLAB_SIZE);
        assert_eq!(reader.length(), SLAB_SIZE);
        let slab = reader.next_slab().unwrap();
        assert_slab(
            &data[SLAB_SIZE..SLAB_SIZE * 2],
            DATA_SHARDS,
            PARITY_SHARDS,
            slab,
        );

        // last 18 bytes of the object
        let n = reader.read_slab(&mut cursor).await.unwrap();
        assert_eq!(n, 18);
        assert_eq!(reader.length(), 18);
        assert!(reader.next_slab().is_none());
        let slab = reader.finish().unwrap();
        assert_eq!(slab.length, 18);
        assert_slab(&data[SLAB_SIZE * 2..], DATA_SHARDS, PARITY_SHARDS, slab);
    }

    #[tokio::test]
    async fn test_slab_reader_overflow() {
        const OVERFLOW_BYTES: usize = 50;
        let mut reader = SlabReader::new(DATA_SHARDS, PARITY_SHARDS);
        let mut data = BytesMut::zeroed(SLAB_SIZE + OVERFLOW_BYTES);
        rand::rng().fill_bytes(&mut data);
        let data = data.freeze();

        let mut cursor = Cursor::new(&data);
        let n = reader.read_slab(&mut cursor).await.unwrap();
        assert_eq!(n, SLAB_SIZE);
        assert_eq!(reader.length(), SLAB_SIZE);

        let n = reader.read_slab(&mut cursor).await.unwrap();
        assert_eq!(n, 0);

        let slab = reader.next_slab().unwrap();
        assert_eq!(slab.length, SLAB_SIZE);
        assert_eq!(slab.shards.len(), DATA_SHARDS + PARITY_SHARDS);
        assert_slab(&data[..SLAB_SIZE], DATA_SHARDS, PARITY_SHARDS, slab);

        assert!(reader.next_slab().is_none());

        let n = reader.read_slab(&mut cursor).await.unwrap();
        assert_eq!(n, OVERFLOW_BYTES);
        assert!(reader.next_slab().is_none());
        let slab = reader.finish().unwrap();
        assert_eq!(slab.length, OVERFLOW_BYTES);
        assert_eq!(slab.shards.len(), DATA_SHARDS + PARITY_SHARDS);
        assert_slab(&data[SLAB_SIZE..], DATA_SHARDS, PARITY_SHARDS, slab);
    }
}
