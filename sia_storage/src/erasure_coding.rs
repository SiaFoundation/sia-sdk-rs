use std::sync::{Arc, OnceLock};

use bytes::{Bytes, BytesMut};
use sia_core::rhp4::{SECTOR_SIZE, SEGMENT_SIZE, SectorRootAccumulator};
use sia_core::types::Hash256;
use sia_reed_solomon::ReedSolomon;
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;

use crate::task::AbortOnDropHandle;

use crate::EncryptionKey;
use crate::encryption::{Chacha20Cipher, encrypt_shard};
use crate::sector_stream::ShardStream;

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

    pub fn total_shards(&self) -> usize {
        self.encoder.total_shards()
    }

    /// Encodes the shards using reed solomon erasure coding, computing the
    /// parity shards and overwriting their values. Rows are independent, so
    /// this works on any equal-length slice of every shard.
    pub fn encode_shards<T: AsRef<[u8]> + AsMut<[u8]>>(&self, shards: &mut [T]) -> Result<()> {
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

/// Bytes of each sector published per step. A slab's rows are parity
/// encoded, encrypted and hashed in steps of this many bytes per sector, and
/// each step is handed to the sector writers as soon as it is done. 256 KiB
/// is 16 steps per sector: the encoder and cipher still run over bulk
/// buffers, and the first bytes leave for the hosts after 2.5 MiB of input
/// instead of after the whole slab. It must be a power of two of segments
/// that divides the sector, for the chunked sector root.
pub(crate) const STEP_BYTES: usize = 256 << 10;

/// How much data is buffered before a single `apply_keystream` call.
const READ_BUFFER_SIZE: usize = 64 << 10;

/// The slab being produced. Created on the first byte of a slab and dropped
/// once its last step is published.
struct ActiveSlab {
    encryption_key: EncryptionKey,
    /// The unpublished tail of every sector. Published steps are split off
    /// the front, so index `i` here is sector offset `published + i`.
    shards: Vec<BytesMut>,
    streams: Vec<Arc<ShardStream>>,
    /// Input bytes landed in this slab.
    length: usize,
    /// Bytes of each sector cut into steps so far.
    published: usize,
    /// The slab's final length, for the slab task. Set by the last step.
    final_length: Arc<OnceLock<usize>>,
    /// Completion of the most recent step, carrying the sector root
    /// accumulators to the next one so steps publish in order.
    prev_step: Option<oneshot::Receiver<Vec<SectorRootAccumulator>>>,
}

/// What the slab task needs when a slab starts: the sector streams it will
/// upload from while the producer fills them.
pub(crate) struct SlabStart {
    pub encryption_key: EncryptionKey,
    pub streams: Vec<Arc<ShardStream>>,
    /// The slab's length in bytes. Set before the streams finish, so it is
    /// there once the last sector has been uploaded.
    pub length: Arc<OnceLock<usize>>,
}

pub(crate) struct ReadProgress {
    /// Bytes read from the reader by this call.
    pub read: usize,
    /// Set when this call read the first byte of a new slab.
    pub started: Option<SlabStart>,
}

/// Interleaves incoming bytes across a slab's data shards and publishes the
/// slab's sectors step by step, so an upload can start sending a sector
/// before the slab is fully read. Reports a [`SlabStart`] when a slab
/// begins; call [`SlabReader::finish`] to pad and publish a trailing partial
/// slab.
pub(crate) struct SlabReader {
    coder: Arc<ErasureCoder>,
    /// Contiguous landing area for incoming data. The object keystream is
    /// applied to it in one call per fill, then the bytes are scattered into
    /// the interleaved shard layout. Allocated once and reused.
    read_buffer: Vec<u8>,
    slab: Option<ActiveSlab>,
    total_length: u64,
    /// Steps still producing, across slabs. Aborted with the reader;
    /// awaited by [`SlabReader::finish`].
    step_tasks: Vec<AbortOnDropHandle<io::Result<()>>>,
}

/// Reads as many bytes as possible from `r` into `buf`, stopping at end of
/// input. Returns the number of bytes read.
///
/// This is distinct from `read_exact`, which reports an unexpected end of input
/// when it cannot fill the buffer.
async fn fill_buf<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut read_total = 0;
    while read_total < buf.len() {
        let n = r.read(&mut buf[read_total..]).await?;
        if n == 0 {
            break;
        }
        read_total += n;
    }
    Ok(read_total)
}

/// One step of a slab, owning only that step's chunk of every sector:
/// parity for its rows, then shard encryption and the chunk's Merkle root
/// per sector, then each chunk frozen for its writers. Steps run on their
/// own tasks, so natively several encode at once on the blocking pool.
fn produce_step(
    coder: &ErasureCoder,
    key: &EncryptionKey,
    offset: usize,
    mut step: Vec<BytesMut>,
) -> Result<Vec<(Bytes, Hash256)>> {
    coder.encode_shards(&mut step)?;
    Ok(step
        .into_iter()
        .enumerate()
        .map(|(i, mut chunk)| {
            encrypt_shard(key, i as u8, offset, &mut chunk);
            let root = SectorRootAccumulator::chunk_root(&chunk);
            (chunk.freeze(), root)
        })
        .collect())
}

impl SlabReader {
    pub(crate) fn new(coder: Arc<ErasureCoder>) -> Self {
        Self {
            coder,
            read_buffer: vec![0u8; READ_BUFFER_SIZE],
            slab: None,
            total_length: 0,
            step_tasks: Vec::new(),
        }
    }

    /// Input bytes in the slab being produced.
    pub fn length(&self) -> usize {
        self.slab.as_ref().map_or(0, |s| s.length)
    }

    pub fn total_length(&self) -> u64 {
        self.total_length
    }

    pub fn optimal_data_size(&self) -> usize {
        self.coder.data_shards() * SECTOR_SIZE
    }

    fn stripe_size(&self) -> usize {
        SEGMENT_SIZE * self.coder.data_shards()
    }

    fn start_slab(&mut self) -> SlabStart {
        let total = self.coder.total_shards();
        let encryption_key: EncryptionKey = rand::random::<[u8; 32]>().into();
        let streams: Vec<_> = (0..total).map(|_| ShardStream::new()).collect();
        let final_length = Arc::new(OnceLock::new());
        self.slab = Some(ActiveSlab {
            encryption_key: encryption_key.clone(),
            shards: (0..total).map(|_| BytesMut::zeroed(SECTOR_SIZE)).collect(),
            streams: streams.clone(),
            length: 0,
            published: 0,
            final_length: final_length.clone(),
            prev_step: None,
        });
        SlabStart {
            encryption_key,
            streams,
            length: final_length,
        }
    }

    /// Reads from `r`, publishing each step of the slab's sectors as its
    /// rows complete, until the slab is full or the reader is done. A call
    /// also returns as soon as it has started a slab, so the caller can
    /// spawn the slab's upload before the next call carries on filling it.
    /// A full slab is completed here and the next call starts a new one.
    pub async fn read_slab<R: AsyncRead + Unpin>(
        &mut self,
        data_key: EncryptionKey,
        r: &mut R,
    ) -> io::Result<ReadProgress> {
        let mut started = None;
        let mut total_read = 0;
        let stripe_size = self.stripe_size();
        let optimal = self.optimal_data_size();
        let mut cipher = None;

        loop {
            // Fill the buffer, then encrypt it in one pass. `want` never
            // exceeds what is left of the slab, so the reader is never taken
            // past the boundary.
            let remaining = optimal - self.length();
            let want = remaining.min(self.read_buffer.len());
            let filled = fill_buf(r, &mut self.read_buffer[..want]).await?;
            if filled == 0 {
                break;
            }
            if self.slab.is_none() {
                started = Some(self.start_slab());
            }
            let slab = self.slab.as_mut().expect("slab started");
            let cipher = cipher.get_or_insert_with(|| {
                Chacha20Cipher::new_v1(data_key.clone(), slab.length as u64, &slab.encryption_key)
            });

            let start_len = slab.length;
            cipher.apply_keystream(&mut self.read_buffer[..filled]);

            let mut off = 0;
            while off < filled {
                let logical = start_len + off;
                let shard_index = (logical % stripe_size) / SEGMENT_SIZE;
                let byte_in_seg = logical % SEGMENT_SIZE;
                let seg_start = (logical / stripe_size) * SEGMENT_SIZE;
                let dst = seg_start + byte_in_seg - slab.published;
                let take = (SEGMENT_SIZE - byte_in_seg).min(filled - off);
                slab.shards[shard_index][dst..dst + take]
                    .copy_from_slice(&self.read_buffer[off..off + take]);
                off += take;
            }

            slab.length += filled;
            self.total_length += filled as u64;
            total_read += filled;

            // Publish every step whose rows are all complete.
            while self.completed_rows_bytes() >= self.published() + STEP_BYTES {
                self.publish_step().await?;
            }
            if self.length() == optimal {
                self.complete_slab().await?;
                break;
            }
            // A short fill means the reader is done. A started slab is
            // handed to the caller before more of it is read.
            if filled < want || started.is_some() {
                break;
            }
        }
        Ok(ReadProgress {
            read: total_read,
            started,
        })
    }

    /// Pads and publishes the rest of a partial slab, then waits for every
    /// step still producing. Nothing to pad when no slab has started since
    /// the last one completed.
    pub async fn finish(&mut self) -> io::Result<()> {
        if self.slab.is_some() {
            self.complete_slab().await?;
        }
        while let Some(task) = self.step_tasks.pop() {
            task.await??;
        }
        Ok(())
    }

    /// Bytes per sector covered by rows that are complete across every data
    /// shard.
    fn completed_rows_bytes(&self) -> usize {
        self.length() / self.stripe_size() * SEGMENT_SIZE
    }

    fn published(&self) -> usize {
        self.slab.as_ref().map_or(0, |s| s.published)
    }

    /// Cuts the remaining steps of the slab, zero padded past its length.
    /// The last step records the slab's length and finishes its streams.
    async fn complete_slab(&mut self) -> io::Result<()> {
        while self.published() < SECTOR_SIZE {
            self.publish_step().await?;
        }
        self.slab = None;
        Ok(())
    }

    /// Cuts the next step off every sector and spawns its production. The
    /// step publishes itself once the step before it has, so chunks reach
    /// the writers in order while the producer reads on.
    async fn publish_step(&mut self) -> io::Result<()> {
        let slab = self.slab.as_mut().expect("slab started");
        let step: Vec<BytesMut> = slab
            .shards
            .iter_mut()
            .map(|s| s.split_to(STEP_BYTES))
            .collect();
        let offset = slab.published;
        slab.published += STEP_BYTES;
        let last = slab.published == SECTOR_SIZE;
        let (done_tx, done_rx) = oneshot::channel();
        let prev = slab.prev_step.replace(done_rx);
        let coder = self.coder.clone();
        let key = slab.encryption_key.clone();
        let streams = slab.streams.clone();
        let final_length = slab.final_length.clone();
        let length = slab.length;

        let task = maybe_spawn!(async move {
            let produced = maybe_spawn_blocking!(
                produce_step(&coder, &key, offset, step).map_err(io::Error::other)
            )?;
            let mut roots = match prev {
                Some(prev) => prev
                    .await
                    .map_err(|_| io::Error::other("the previous step of the slab was abandoned"))?,
                None => streams
                    .iter()
                    .map(|_| SectorRootAccumulator::new())
                    .collect::<Vec<_>>(),
            };
            for ((stream, root), (chunk, chunk_root)) in
                streams.iter().zip(roots.iter_mut()).zip(produced)
            {
                root.insert_chunk_root(chunk_root, STEP_BYTES);
                stream.push(chunk);
            }
            if last {
                let _ = final_length.set(length);
                for (stream, root) in streams.iter().zip(&roots) {
                    stream.finish(root.root());
                }
            }
            let _ = done_tx.send(roots);
            Ok::<_, io::Error>(())
        });
        self.step_tasks.retain(|task| !task.is_finished());
        self.step_tasks.push(AbortOnDropHandle::new(task));
        // On a single-threaded runtime the step and the writers only run
        // when the producer yields; give them the step before reading on.
        tokio::task::yield_now().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::sector_stream::SectorBody;

    fn init_shard(i: u8) -> Vec<u8> {
        vec![i; SECTOR_SIZE]
    }

    /// Reverses the per-segment encryption `read_slab` applies, restoring the
    /// data shards to plaintext so the striping assertions can compare against
    /// the original input. Mirrors `read_slab`'s logical-order walk.
    fn decrypt_data_shards(
        shards: &mut [Vec<u8>],
        data_shards: usize,
        data_key: &EncryptionKey,
        slab_key: &EncryptionKey,
        length: usize,
    ) {
        let mut cipher = Chacha20Cipher::new_v1(data_key.clone(), 0, slab_key);
        let stripe = SEGMENT_SIZE * data_shards;
        let mut p = 0;
        while p < length {
            let shard = (p % stripe) / SEGMENT_SIZE;
            let seg_start = (p / stripe) * SEGMENT_SIZE;
            let n = SEGMENT_SIZE.min(length - p);
            cipher.apply_keystream(&mut shards[shard][seg_start..seg_start + n]);
            p += n;
        }
    }

    #[sia_core_derive::cross_target_test]
    fn test_encode_shards() {
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

    /// Drives `read_slab` until the reader is exhausted or a slab completes,
    /// as `Upload::read` does, returning the bytes read and the slab.
    async fn read_whole<R: AsyncRead + Unpin>(
        reader: &mut SlabReader,
        data_key: &EncryptionKey,
        r: &mut R,
    ) -> (usize, SlabStart) {
        let mut total = 0;
        let mut slab = None;
        loop {
            let progress = reader.read_slab(data_key.clone(), r).await.unwrap();
            total += progress.read;
            if let Some(started) = progress.started {
                assert!(slab.is_none(), "a second slab started");
                slab = Some(started);
            }
            // A completed slab resets the reader's length to zero.
            let complete = slab.is_some() && reader.length() == 0;
            if progress.read == 0 || complete {
                return (total, slab.expect("the first byte starts a slab"));
            }
        }
    }

    /// Reads a slab's sectors back out of its streams, checks each root
    /// against a whole-sector hash, and undoes the shard encryption, leaving
    /// the object-keystream-encrypted data shards and the parity over them.
    async fn collect_sectors(slab: &SlabStart) -> Vec<Vec<u8>> {
        let mut shards = Vec::new();
        for (i, stream) in slab.streams.iter().enumerate() {
            let mut body = SectorBody::new(stream.clone());
            let mut shard = Vec::with_capacity(SECTOR_SIZE);
            while let Some(chunk) = body.next_chunk().await {
                shard.extend_from_slice(&chunk);
            }
            assert_eq!(shard.len(), SECTOR_SIZE, "shard {i} length");
            assert_eq!(
                body.root().await,
                sia_core::rhp4::sector_root(&shard),
                "shard {i} chunked root"
            );
            encrypt_shard(&slab.encryption_key, i as u8, 0, &mut shard);
            shards.push(shard);
        }
        shards
    }

    #[sia_core_derive::cross_target_test]
    async fn test_striped_read() {
        const DATA_SHARDS: usize = 3;
        const PARITY_SHARDS: usize = 2;
        const SLAB_SIZE: usize = SECTOR_SIZE * DATA_SHARDS;

        let test_cases = vec![
            // (data size, expected size)
            (100, 100),                 // under
            (SLAB_SIZE, SLAB_SIZE),     // exact
            (2 * SLAB_SIZE, SLAB_SIZE), // over
        ];

        for (data_size, expected_size) in test_cases {
            let mut data = vec![0u8; data_size];
            getrandom::fill(&mut data).unwrap();

            let data_key = EncryptionKey::from([7u8; 32]);
            let coder = Arc::new(ErasureCoder::new(DATA_SHARDS, PARITY_SHARDS).unwrap());
            let mut reader = SlabReader::new(coder.clone());
            let (read, slab) =
                read_whole(&mut reader, &data_key, &mut Cursor::new(data.clone())).await;
            assert_eq!(read, expected_size, "data size {data_size} read mismatch");
            if data_size < SLAB_SIZE {
                assert!(
                    slab.length.get().is_none(),
                    "data size {data_size} should not complete a slab"
                );
            }
            reader.finish().await.unwrap();
            let size = *slab.length.get().expect("slab complete");
            let mut shards = collect_sectors(&slab).await;

            // The parity published step by step matches one encode of the
            // whole data shards.
            let mut expected = shards.clone();
            coder.encode_shards(&mut expected).unwrap();
            assert_eq!(shards, expected, "data size {data_size} parity mismatch");

            decrypt_data_shards(
                &mut shards,
                DATA_SHARDS,
                &data_key,
                &slab.encryption_key,
                size,
            );

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

    #[sia_core_derive::cross_target_test]
    async fn test_striped_read_write() {
        const DATA_SHARDS: usize = 4;
        const PARITY_SHARDS: usize = 1;
        let coder = Arc::new(ErasureCoder::new(DATA_SHARDS, PARITY_SHARDS).unwrap());

        let mut data = vec![0u8; SECTOR_SIZE * 7 / 2]; // 3.5 shards of data
        data[..SECTOR_SIZE].fill(1);
        data[SECTOR_SIZE..2 * SECTOR_SIZE].fill(2);
        data[2 * SECTOR_SIZE..3 * SECTOR_SIZE].fill(3);
        data[3 * SECTOR_SIZE..].fill(4);
        let data = Bytes::from(data);

        let data_key = EncryptionKey::from([7u8; 32]);
        let mut reader = SlabReader::new(coder.clone());
        let (read, slab) = read_whole(&mut reader, &data_key, &mut Cursor::new(data.clone())).await;
        assert_eq!(read, data.len());
        assert!(slab.length.get().is_none()); // 3.5 shards doesn't fill a 4-shard slab
        reader.finish().await.unwrap();
        let size = *slab.length.get().expect("slab complete");
        let mut shards = collect_sectors(&slab).await;
        let mut expected = shards.clone();
        coder.encode_shards(&mut expected).unwrap();
        assert_eq!(shards, expected, "parity matches a re-encode");
        decrypt_data_shards(
            &mut shards,
            DATA_SHARDS,
            &data_key,
            &slab.encryption_key,
            size,
        );
        assert_eq!(size, data.len());

        assert_eq!(shards.len(), 5);
        assert_eq!(size, SECTOR_SIZE * 7 / 2);

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

    #[sia_core_derive::cross_target_test]
    fn test_erasure_code_golden() {
        use blake2b_simd::Params;
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
            for chunk in buf.as_chunks_mut::<8>().0 {
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
            let got: Hash256 = Params::new()
                .hash_length(32)
                .to_state()
                .update(shard)
                .finalize()
                .into();
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
                let got: Hash256 = Params::new()
                    .hash_length(32)
                    .to_state()
                    .update(shard)
                    .finalize()
                    .into();
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
