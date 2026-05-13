use std::mem;

use bytes::Bytes;
use sia_core::rhp4::{SECTOR_SIZE, SEGMENT_SIZE};
use sia_reed_solomon::ReedSolomon;
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Error)]
pub enum Error {
    #[error("ReedSolomon error: {0}")]
    ReedSolomon(#[from] sia_reed_solomon::Error),

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
        self.encoder.data_shards()
    }

    /// encodes the shards using reed solomon erasure coding,
    /// computing the parity shards and overwriting their values.
    pub fn encode_shards(&self, shards: &mut [Vec<u8>]) -> Result<()> {
        self.encoder.encode(shards)?;
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
    shards: Vec<Vec<u8>>,
    length: usize,
    total_length: u64,
}

pub(crate) struct ReadSlab {
    pub length: usize,
    pub shards: Vec<Vec<u8>>,
}

impl SlabReader {
    pub(crate) fn new(data_shards: usize, parity_shards: usize) -> Self {
        let total_shards = data_shards + parity_shards;
        Self {
            data_shards,
            shards: vec![vec![0u8; SECTOR_SIZE]; total_shards],
            length: 0,
            total_length: 0,
        }
    }

    pub fn length(&self) -> usize {
        self.length
    }

    /// Cumulative bytes that have landed in the pipeline across all
    /// `read_slab` calls, including bytes from reads that errored part-way.
    /// Unlike [length](Self::length), this never resets when a slab is
    /// finalized.
    pub fn total_length(&self) -> u64 {
        self.total_length
    }

    /// The optimal slab size for streaming reads
    pub fn optimal_data_size(&self) -> usize {
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
        let remaining = self.optimal_data_size() - self.length;
        if remaining == 0 {
            return Ok((0, None));
        }
        let mut r = r.take(remaining as u64);
        let mut total_read = 0;
        loop {
            if self.length == self.optimal_data_size() {
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
            self.total_length += n as u64;
            total_read += n;
        }
        let slab = if self.length == self.optimal_data_size() {
            let length = mem::take(&mut self.length);
            let total_shards = self.shards.len();
            let shards = mem::replace(&mut self.shards, vec![vec![0u8; SECTOR_SIZE]; total_shards]);
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

    fn init_shard(i: u8) -> Vec<u8> {
        vec![i; SECTOR_SIZE]
    }

    cross_target_tests! {
    async fn test_encode_shards() {
        let data_shards = 2;
        let parity_shards = 3;
        let coder = ErasureCoder::new(data_shards, parity_shards).unwrap();

        let mut shards: Vec<Vec<u8>> = [
            init_shard(1),
            init_shard(2),
            init_shard(0),
            init_shard(0),
            init_shard(0),
        ]
        .into();

        coder.encode_shards(&mut shards).unwrap();

        let expected_shards: Vec<Vec<u8>> = vec![
            init_shard(1),
            init_shard(2),
            init_shard(7),  // parity shard 1
            init_shard(4),  // parity shard 2
            init_shard(13), // parity shard 3
        ];
        assert_eq!(shards, expected_shards);

        // reconstruct data shards
        for i in 0..data_shards {
            let mut shards: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
            shards[i] = None;
            coder.reconstruct_data_shards(&mut shards).unwrap();
            let shards: Vec<Vec<u8>> = shards.into_iter().map(|s| s.unwrap()).collect();
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

        let mut data = vec![0u8; SECTOR_SIZE * 7 / 2]; // 3.5 shards of data
        data[..SECTOR_SIZE].fill(1);
        data[SECTOR_SIZE..2 * SECTOR_SIZE].fill(2);
        data[2 * SECTOR_SIZE..3 * SECTOR_SIZE].fill(3);
        data[3 * SECTOR_SIZE..].fill(4);
        let data = Bytes::from(data);

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
        assert_eq!(shards[4], vec![0u8; SECTOR_SIZE]); // parity shard should be empty

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
        assert_ne!(shards[4], vec![0u8; SECTOR_SIZE]);

        // joining the shards back together should result in the original data
        let shards: Vec<Bytes> = shards.into_iter().map(Bytes::from).collect();
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

    async fn test_erasure_code_golden() {
        use sia_core::blake2::{Blake2b256, Digest};
        use sia_core::hash_256;
        use sia_core::types::Hash256;

        // Golden hashes generated by a 10-of-30 RS slab with klauspost/reedsolomon in Go.
        // The data shards are generated using a simple xorshift64 PRNG since Go and Rust
        // do not share a PRNG that would guarantee parity.
        const EXPECTED_SHARD_HASHES: [Hash256; 30] = [
            // data shards
            hash_256!("5f9133b3f31ca9e40e029fd0b0fc31127803ba39bbc6393da17f201c2b320bc0"),
            hash_256!("873f9a6c0bfb4063b3125f034b0adbafec4c6a3cf4855381640612d3bdb52c52"),
            hash_256!("addeec9b79e16ef8b73faa44acdd8bce937baf4261e0a2960fad431378163c9a"),
            hash_256!("99c7af0efa1aee38039171a95550735f7ba85f2cc53b5d211177a4714261067f"),
            hash_256!("7c6619b96e1518270e8a6098558d92c6f599500a4c4a07c2b1c378f1c28f81d2"),
            hash_256!("e4a27ad70588b5fe9b1eab2c3e90b2400f9b835870314d5462af677fa0194b65"),
            hash_256!("28fde42094bb60c92aef3f4c1b76ef3b41407b4f32980d1487bacd3439fc1c38"),
            hash_256!("49a89238c935b6dbfae3081785ce008b1e6c5b17e64e87e6a977146956708e95"),
            hash_256!("fe4604077368a0da69257ad0f6d4a81c1d2ecb95100b320f837c190aee42197a"),
            hash_256!("80bed93006c4e0a4f2aca7ee2da737271d6df50b117c1ba4012ad06381b45a84"),
            // parity shards
            hash_256!("d0820641e4a40d01aa61812561717a45681e0d9d990daff41971e0e4bbb9596f"),
            hash_256!("c93ede3459a43f28a73d6b54618891d218fe2a6fff72e8a2e11ddcc8f3c03ce3"),
            hash_256!("240cb1f10fb2539f287af32dab1271b37896dd72ce63e9df4dc528abe65a260c"),
            hash_256!("85315fa52dcc04496815bc6d988a0b2caa7a872957739fd2e1aac5189e756fcf"),
            hash_256!("7c5c6545793751788dd8e401d46b0567cb34bc2ee31097e1ec2108c6e01511a6"),
            hash_256!("24bfd4acab06d4976f08219b6fb5dc872b1382f39961f23b5d09065d137f423f"),
            hash_256!("fd3140df262ab81f99f1f5a4ee83a2d06f2f361b538a4949b651ad2bc24e7be5"),
            hash_256!("46cab3709634583d2fe357d62f8a30c4797ea26696ecfb7957b3bb5168787cfc"),
            hash_256!("babf9e26da954f409e2fb8834fddf2c075daa8789c62c03a2cc649296b3ad0ee"),
            hash_256!("08cd570feba44f78705f0b3fd5fc973bcd62beb16567c700a3671a316af6a71b"),
            hash_256!("a56df2e4f7be6626861da81b83e812315870ff89d0854cf290a2e42ccb64358f"),
            hash_256!("5264c29cfd9fe9c63cdefed4ca20c790ed30c9ff2bfd9c167bf5205d797f9f00"),
            hash_256!("9f1c15a3a5514581eb0e20b3811b92fcf4f59cdbd986ea2677d40f65e728aa33"),
            hash_256!("aaaa12e1c177e5e52012068462b83e9a0ce2c6d74d089cbdf4b370186ac386ad"),
            hash_256!("99f837946ab86c68b451693685041b88aa66ff1330ff2d0c54c87e87cec5640b"),
            hash_256!("7fc2ffab8e8c85898b2d6a225b85771cd8ceeea61306710f14f07c94076e267c"),
            hash_256!("9ff3bfbd1f282f9ef3705715321a687cfe7f1f8d623ef153e1ebbdb9ad4493db"),
            hash_256!("a922d41284f8c6c8c0d764fcd0df2f5313e84abd594787e94a097ceded6dd912"),
            hash_256!("4b8f9c5558cd26029a120b30b8429a28f17869c283402c0dd8e8c390fb7639c7"),
            hash_256!("1bdc7fdb4c601c503bf12a833a12a0a41ed717db7ee1c99ce3176ba8afeb2684"),
        ];
        const DATA_SHARDS: usize = 10;
        const PARITY_SHARDS: usize = 20;

        fn fill_shard(buf: &mut [u8], seed: u64) {
            let mut state = seed;
            for chunk in buf.chunks_exact_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes());
            }
        }

        let mut shards: Vec<Vec<u8>> = (0..DATA_SHARDS + PARITY_SHARDS)
            .map(|_| vec![0u8; SECTOR_SIZE])
            .collect();
        for (i, shard) in shards[..DATA_SHARDS].iter_mut().enumerate() {
            fill_shard(shard, i as u64 + 1);
        }

        let coder = ErasureCoder::new(DATA_SHARDS, PARITY_SHARDS).unwrap();
        coder.encode_shards(&mut shards).unwrap();

        for (i, shard) in shards.iter().enumerate() {
            let got: Hash256 = Blake2b256::new().chain_update(shard).finalize().into();
            assert_eq!(got, EXPECTED_SHARD_HASHES[i], "shard {i} hash mismatch");
        }

        let check_reconstruct = |dropped: &[usize], label: &str| {
            let mut opt: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
            for &i in dropped {
                opt[i] = None;
            }
            coder.reconstruct_data_shards(&mut opt).unwrap();
            for i in 0..DATA_SHARDS {
                let shard = opt[i].as_ref().expect("data shard reconstructed");
                let got: Hash256 = Blake2b256::new().chain_update(shard).finalize().into();
                assert_eq!(got, EXPECTED_SHARD_HASHES[i], "{label}: shard {i} mismatch");
            }
        };

        // each data shard dropped individually
        for drop in 0..DATA_SHARDS {
            check_reconstruct(&[drop], &format!("drop_{drop}"));
        }
        // every data shard missing, rebuild from parity alone
        let all_data: Vec<usize> = (0..DATA_SHARDS).collect();
        check_reconstruct(&all_data, "all_data");
        // minimum remaining: drop 20 shards (all data + half of parity), leaving DATA_SHARDS parity shards
        let min_remaining: Vec<usize> = (0..PARITY_SHARDS).collect();
        check_reconstruct(&min_remaining, "min_remaining");
    }
    }
}
