//! A sector that is sent while it is still being produced.
//!
//! The slab producer publishes each sector's bytes in order, a chunk at a
//! time, and every write attempt for that sector reads them back through a
//! [`SectorBody`] from the start. A retry or a racer that begins mid-slab
//! sends the finished prefix immediately and then follows production; one
//! that begins after the sector is complete sends it like any buffered
//! sector. The chunks stay in memory until the slab is pinned, exactly as
//! the whole sector did before.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use sia_core::rhp4::SECTOR_SIZE;
use sia_core::types::Hash256;
use tokio::sync::Notify;

struct State {
    chunks: Vec<Bytes>,
    /// Bytes published so far.
    len: usize,
    /// Bytes the sector will have; the body ends when `len` reaches it.
    total: usize,
    /// Set once by the producer, over the complete sector.
    root: Option<Hash256>,
}

/// One sector's bytes as they are produced, shared between the producer and
/// every write attempt.
pub(crate) struct ShardStream {
    state: Mutex<State>,
    notify: Notify,
}

impl ShardStream {
    /// A sector of [`SECTOR_SIZE`] bytes that the producer will fill.
    pub(crate) fn new() -> Arc<Self> {
        Self::with_total(SECTOR_SIZE)
    }

    fn with_total(total: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                chunks: Vec::new(),
                len: 0,
                total,
                root: None,
            }),
            notify: Notify::new(),
        })
    }

    /// A sector that is already complete. Its root is computed here when it
    /// is a whole sector, so it is ready for the host's reply.
    #[cfg(test)]
    pub(crate) fn complete(data: Bytes) -> Arc<Self> {
        let root = (data.len() == SECTOR_SIZE).then(|| sia_core::rhp4::sector_root(&data));
        let stream = Self::with_total(data.len());
        {
            let mut state = stream.state.lock().unwrap();
            state.len = data.len();
            state.chunks.push(data);
            state.root = root;
        }
        stream
    }

    /// Publishes the next chunk, in order.
    pub(crate) fn push(&self, chunk: Bytes) {
        let mut state = self.state.lock().unwrap();
        state.len += chunk.len();
        debug_assert!(state.len <= state.total, "sector overfilled");
        state.chunks.push(chunk);
        drop(state);
        self.notify.notify_waiters();
    }

    /// Records the root once every chunk has been pushed.
    pub(crate) fn finish(&self, root: Hash256) {
        let mut state = self.state.lock().unwrap();
        debug_assert_eq!(state.len, state.total, "sector finished before it was full");
        state.root = Some(root);
        drop(state);
        self.notify.notify_waiters();
    }

    /// Bytes the sector will have once complete.
    pub(crate) fn total(&self) -> usize {
        self.state.lock().unwrap().total
    }

    /// Chunk `index`, waiting for the producer if it is not published yet.
    /// `None` once the body is complete and `index` is past its end.
    async fn chunk(&self, index: usize) -> Option<Bytes> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Arm before checking so a push between the check and the await
            // still wakes this task.
            notified.as_mut().enable();
            {
                let state = self.state.lock().unwrap();
                if let Some(chunk) = state.chunks.get(index) {
                    return Some(chunk.clone());
                }
                if state.len >= state.total {
                    return None;
                }
            }
            notified.await;
        }
    }

    /// The sector root, waiting for the producer to finish.
    pub(crate) async fn root(&self) -> Hash256 {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(root) = self.state.lock().unwrap().root {
                return root;
            }
            notified.await;
        }
    }
}

/// One write attempt's view of a sector: the chunks in order, then the
/// root. Each attempt gets its own, starting from the first chunk.
pub(crate) struct SectorBody {
    stream: Arc<ShardStream>,
    next: usize,
}

impl SectorBody {
    pub(crate) fn new(stream: Arc<ShardStream>) -> Self {
        Self { stream, next: 0 }
    }

    /// A body over a sector that is already complete.
    #[cfg(test)]
    pub(crate) fn from_bytes(data: Bytes) -> Self {
        Self::new(ShardStream::complete(data))
    }

    /// Bytes the body will deliver in total.
    pub(crate) fn len(&self) -> usize {
        self.stream.total()
    }

    /// The next chunk, waiting for the producer when necessary. `None` at
    /// the end of the body.
    pub(crate) async fn next_chunk(&mut self) -> Option<Bytes> {
        let chunk = self.stream.chunk(self.next).await?;
        self.next += 1;
        Some(chunk)
    }

    /// The root of the whole sector, available once the producer finished.
    pub(crate) async fn root(&self) -> Hash256 {
        self.stream.root().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body started before production delivers the prefix, then follows
    /// the producer; one started afterwards delivers everything at once.
    #[sia_core_derive::cross_target_test]
    async fn bodies_follow_production() {
        let stream = ShardStream::with_total(6);
        stream.push(Bytes::from_static(b"ab"));

        let mut early = SectorBody::new(stream.clone());
        assert_eq!(early.next_chunk().await.unwrap(), "ab");

        let producer = stream.clone();
        let waiter = maybe_spawn!(async move {
            let mut got = Vec::new();
            let mut body = SectorBody::new(producer);
            while let Some(chunk) = body.next_chunk().await {
                got.extend_from_slice(&chunk);
            }
            (got, body.root().await)
        });

        stream.push(Bytes::from_static(b"cd"));
        stream.push(Bytes::from_static(b"ef"));
        stream.finish(Hash256::from([9u8; 32]));

        assert_eq!(early.next_chunk().await.unwrap(), "cd");
        assert_eq!(early.next_chunk().await.unwrap(), "ef");
        assert!(early.next_chunk().await.is_none());
        let (got, root) = waiter.await.unwrap();
        assert_eq!(got, b"abcdef");
        assert_eq!(root, Hash256::from([9u8; 32]));

        let mut late = SectorBody::new(stream);
        let mut got = Vec::new();
        while let Some(chunk) = late.next_chunk().await {
            got.extend_from_slice(&chunk);
        }
        assert_eq!(got, b"abcdef");
    }
}
