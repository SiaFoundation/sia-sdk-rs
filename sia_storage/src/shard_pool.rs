use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use sia_core::rhp4::SECTOR_SIZE;

#[cfg(not(target_arch = "wasm32"))]
type Buf = memmap2::MmapMut;
#[cfg(target_arch = "wasm32")]
type Buf = bytes::BytesMut;

/// Free list of sector-sized anonymous mappings for one upload.
pub(crate) struct ShardPool {
    free: Mutex<Vec<Buf>>,
    max: usize,
    #[cfg(test)]
    allocated: AtomicUsize,
}

/// A sector-sized buffer borrowed from a [`ShardPool`]. Returns to the pool on
/// drop.
pub(crate) struct PooledShard {
    buf: Option<Buf>,
    pool: Arc<ShardPool>,
}

#[cfg(not(target_arch = "wasm32"))]
fn map_sector() -> io::Result<Buf> {
    memmap2::MmapMut::map_anon(SECTOR_SIZE)
}

#[cfg(target_arch = "wasm32")]
fn map_sector() -> io::Result<Buf> {
    Ok(bytes::BytesMut::zeroed(SECTOR_SIZE))
}

impl ShardPool {
    /// Creates a pool that keeps at most `max` idle buffers.
    pub(crate) fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            free: Mutex::new(Vec::new()),
            max,
            #[cfg(test)]
            allocated: AtomicUsize::new(0),
        })
    }

    /// Pops an idle buffer or maps a zeroed one. Never waits.
    pub(crate) fn take(self: &Arc<Self>) -> io::Result<PooledShard> {
        let idle = self.free.lock().unwrap().pop();
        let buf = match idle {
            Some(buf) => buf,
            None => {
                #[cfg(test)]
                self.allocated.fetch_add(1, Ordering::Relaxed);
                map_sector()?
            }
        };
        Ok(PooledShard {
            buf: Some(buf),
            pool: self.clone(),
        })
    }

    pub(crate) fn take_slab(self: &Arc<Self>, n: usize) -> io::Result<Vec<PooledShard>> {
        (0..n).map(|_| self.take()).collect()
    }

    #[cfg(test)]
    pub(crate) fn allocated(&self) -> usize {
        self.allocated.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn idle(&self) -> usize {
        self.free.lock().unwrap().len()
    }

    fn recycle(&self, buf: Buf) {
        let mut free = self.free.lock().unwrap();
        if free.len() < self.max {
            free.push(buf);
        }
    }
}

impl PooledShard {
    fn inner(&self) -> &Buf {
        self.buf.as_ref().expect("buffer is taken only in drop")
    }

    fn inner_mut(&mut self) -> &mut Buf {
        self.buf.as_mut().expect("buffer is taken only in drop")
    }
}

impl AsRef<[u8]> for PooledShard {
    fn as_ref(&self) -> &[u8] {
        self.inner()
    }
}

impl AsMut<[u8]> for PooledShard {
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner_mut()
    }
}

impl Deref for PooledShard {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.inner()
    }
}

impl DerefMut for PooledShard {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.inner_mut()
    }
}

impl Drop for PooledShard {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.recycle(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[sia_core_derive::cross_target_test]
    fn test_take_reuses_recycled_buffer() {
        let pool = ShardPool::new(4);
        let first = pool.take().unwrap();
        let ptr = first.as_ptr();
        assert_eq!(first.len(), SECTOR_SIZE);
        assert!(first.iter().all(|&b| b == 0), "fresh buffer must be zeroed");
        drop(first);
        assert_eq!(pool.idle(), 1);

        let second = pool.take().unwrap();
        assert_eq!(second.as_ptr(), ptr, "recycled buffer must be reused");
        assert_eq!(pool.allocated(), 1);
        assert_eq!(pool.idle(), 0);
    }

    #[sia_core_derive::cross_target_test]
    fn test_recycle_caps_idle_buffers() {
        let pool = ShardPool::new(2);
        let shards = pool.take_slab(3).unwrap();
        assert_eq!(pool.allocated(), 3);
        drop(shards);
        assert_eq!(pool.idle(), 2, "idle buffers above max must be dropped");

        let _shards = pool.take_slab(2).unwrap();
        assert_eq!(pool.allocated(), 3, "idle buffers must be reused first");
        assert_eq!(pool.idle(), 0);
    }

    #[sia_core_derive::cross_target_test]
    fn test_owned_bytes_recycle_on_last_handle() {
        let pool = ShardPool::new(1);
        let mut shard = pool.take().unwrap();
        shard.fill(7);
        let ptr = shard.as_ptr();

        let a = Bytes::from_owner(shard);
        assert_eq!(a.as_ptr(), ptr, "from_owner must not copy");
        let b = a.clone();
        drop(a);
        assert_eq!(pool.idle(), 0, "a live clone must keep the buffer out");
        assert!(b.iter().all(|&x| x == 7));
        drop(b);
        assert_eq!(pool.idle(), 1, "last handle must recycle the buffer");

        let again = pool.take().unwrap();
        assert_eq!(again.as_ptr(), ptr);
        assert_eq!(pool.allocated(), 1);
    }
}
