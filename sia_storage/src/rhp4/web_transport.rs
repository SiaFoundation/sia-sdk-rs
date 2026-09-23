//! WebTransport-based RHP4 client for WASM targets.
//!
//! Provides a [`Client`] that implements [`super::Transport`] using the
//! browser's WebTransport API, mirroring the siamux client on native.
//! Connections are pooled per host — one WebTransport session per host,
//! with multiple bidirectional streams for concurrent RPCs.
//!
//! Writes use direct `JsFuture` calls (`write_all_async`) to avoid tokio
//! poll overhead. Reads use `AsyncRead` — the JS `reader.read()` already
//! returns large chunks which are buffered internally.

use std::cell::RefCell;
use std::collections::HashMap;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll};

use bytes::Bytes;
use js_sys::Uint8Array;
use log::debug;
use sia_core::rhp4::protocol::{RPCReadSector, RPCSettings, RPCWriteSector};
use sia_core::rhp4::{AccountToken, HostPrices};
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;
use sia_core::types::v2::Protocol;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::{Semaphore, watch};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::time::{Duration, Instant, timeout};

use super::{Error, HostEndpoint, Transport};

#[wasm_bindgen]
extern "C" {
    type ReadableStreamReadResult;

    #[wasm_bindgen(method, getter, js_name = "done")]
    fn is_done(this: &ReadableStreamReadResult) -> bool;

    #[wasm_bindgen(method, getter)]
    fn value(this: &ReadableStreamReadResult) -> JsValue;
}

/// The WebTransport URL path for the RHP4 protocol.
const RHP4_PATH: &str = "/sia/rhp/v4";

/// Maximum concurrent in-flight dials.
const MAX_PENDING_CONNS: usize = 4;

/// Timeout for establishing a WebTransport session to one address.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for opening a bidirectional stream on an established connection.
/// Independent of the per-RPC timeout so a hung `create_bidirectional_stream`
/// can't consume the caller's full RPC budget.
const OPEN_STREAM_TIMEOUT: Duration = Duration::from_secs(10);

fn js_err_message(e: &JsValue) -> String {
    if let Some(err) = e.dyn_ref::<js_sys::Error>() {
        let message: String = err.message().into();
        if message.is_empty() {
            return "JavaScript error with no message".to_string();
        }
        return message;
    }
    e.as_string().unwrap_or_else(|| format!("{e:?}"))
}

// --- Connection ---

/// A WebTransport connection to a host. Supports opening multiple
/// bidirectional streams for sequential RPCs without reconnecting.
struct Connection {
    transport: web_sys::WebTransport,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.transport.close();
    }
}

impl Connection {
    async fn open_stream(&self) -> Result<Stream, Error> {
        let bidi: web_sys::WebTransportBidirectionalStream = timeout(
            OPEN_STREAM_TIMEOUT,
            JsFuture::from(self.transport.create_bidirectional_stream()),
        )
        .await
        .map_err(|_| Error::Transport("createBidirectionalStream: timeout".into()))?
        .map_err(|e| {
            Error::Transport(format!("createBidirectionalStream: {}", js_err_message(&e)))
        })?
        .unchecked_into();
        let reader = bidi
            .readable()
            .get_reader()
            .unchecked_into::<web_sys::ReadableStreamDefaultReader>();
        let writer = bidi
            .writable()
            .get_writer()
            .map_err(|e| Error::Transport(format!("get_writer: {}", js_err_message(&e))))?;
        Ok(Stream::new(reader, writer))
    }
}

async fn connect(addr: &str) -> Result<Connection, Error> {
    let url = if addr.starts_with("https://") {
        addr.to_string()
    } else if addr.contains('/') {
        format!("https://{addr}")
    } else {
        format!("https://{addr}{RHP4_PATH}")
    };
    debug!("[WT] connecting to {url}");

    let options = web_sys::WebTransportOptions::new();
    let wt = web_sys::WebTransport::new_with_options(&url, &options).map_err(|e| {
        Error::Transport(format!("WebTransport constructor: {}", js_err_message(&e)))
    })?;

    let conn = Connection { transport: wt };

    // Attach a handler to `.closed` before awaiting ready — the session can
    // fail during the handshake, and if the future here is dropped (or ready
    // rejects after we've moved on), `Connection::drop` will call `close()`
    // on a transport whose `.closed` Promise is about to reject with a
    // `WebTransportError`. Without a handler attached, that rejection reaches
    // the browser's global unhandled-rejection handler. Transport errors are
    // already reported via individual read/write failures and pool eviction,
    // so this handler just logs and swallows.
    let closed = conn.transport.closed();
    let log_url = url.clone();
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = JsFuture::from(closed).await {
            debug!(
                "[WT] session closed with error: {log_url}: {}",
                js_err_message(&e)
            );
        }
    });

    JsFuture::from(conn.transport.ready())
        .await
        .map_err(|e| Error::Transport(format!("WebTransport ready: {}", js_err_message(&e))))?;

    debug!("[WT] connected to {url}");
    Ok(conn)
}

// --- Stream ---

/// One bidirectional stream carrying a single RPC. Reads go through
/// [`AsyncRead`]; writes bypass poll entirely via [`Stream::write_all_async`].
struct Stream {
    reader: web_sys::ReadableStreamDefaultReader,
    pending_read: Option<JsFuture>,
    /// Unread tail of the last chunk from `reader`, as a view into the JS
    /// chunk rather than a copy.
    leftover: Option<Uint8Array>,
    writer: web_sys::WritableStreamDefaultWriter,
}

impl Stream {
    fn new(
        reader: web_sys::ReadableStreamDefaultReader,
        writer: web_sys::WritableStreamDefaultWriter,
    ) -> Self {
        Self {
            reader,
            pending_read: None,
            leftover: None,
            writer,
        }
    }

    /// Write all bytes in one JS call. This bypasses tokio's poll-based
    /// AsyncWrite which would yield to the JS event loop on every poll.
    /// RPC requests are encoded into a Vec<u8> first, then sent here.
    async fn write_all_async(&self, data: &[u8]) -> Result<(), std::io::Error> {
        let array = Uint8Array::new_with_length(data.len() as u32);
        array.copy_from(data);
        JsFuture::from(self.writer.write_with_chunk(&array))
            .await
            .map_err(|e| std::io::Error::other(js_err_message(&e)))?;
        Ok(())
    }
}

/// Explicitly close both halves of the bidirectional stream when dropped.
/// Without this, the browser holds the underlying transport resources
/// alive until the JS stream wrappers are garbage-collected
impl Drop for Stream {
    fn drop(&mut self) {
        let reader = self.reader.clone();
        let writer = self.writer.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let _ = JsFuture::from(writer.close()).await;
            let _ = JsFuture::from(reader.cancel()).await;
        });
    }
}

/// Copies as much of `chunk` as fits into `buf`, straight from JS memory,
/// and returns the unread tail as a view into the same chunk.
fn fill_from_chunk(chunk: Uint8Array, buf: &mut ReadBuf<'_>) -> Option<Uint8Array> {
    let len = chunk.length();
    let n = len.min(buf.remaining() as u32);
    chunk
        .subarray(0, n)
        .copy_to(buf.initialize_unfilled_to(n as usize));
    buf.advance(n as usize);
    (n < len).then(|| chunk.subarray(n, len))
}

/// AsyncRead for reading RPC responses. The JS `reader.read()` returns
/// large chunks naturally; whatever the caller's buffer cannot take is kept
/// in `self.leftover` for the next poll.
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if let Some(chunk) = this.leftover.take() {
            this.leftover = fill_from_chunk(chunk, buf);
            return Poll::Ready(Ok(()));
        }

        if this.pending_read.is_none() {
            this.pending_read = Some(JsFuture::from(this.reader.read()));
        }

        let future = this.pending_read.as_mut().unwrap();
        let result = std::task::ready!(Pin::new(future).poll(cx))
            .map_err(|e| std::io::Error::other(js_err_message(&e)))?;
        this.pending_read = None;

        let chunk: ReadableStreamReadResult = result.unchecked_into();
        if chunk.is_done() {
            return Poll::Ready(Ok(()));
        }

        this.leftover = fill_from_chunk(Uint8Array::new(&chunk.value()), buf);
        Poll::Ready(Ok(()))
    }
}

// --- Client with connection pooling ---

/// `None` while the dial is in flight.
type DialOutcome = Option<Result<Rc<Connection>, String>>;

type PoolEntry = watch::Receiver<DialOutcome>;

#[derive(Clone)]
pub struct Client {
    pool: Rc<RefCell<HashMap<PublicKey, PoolEntry>>>,
    dial_sema: Rc<Semaphore>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Client {
            pool: Rc::new(RefCell::new(HashMap::new())),
            dial_sema: Rc::new(Semaphore::new(MAX_PENDING_CONNS)),
        }
    }

    /// Returns the pooled connection for the host, dialing it if necessary.
    async fn connection(&self, host: &HostEndpoint) -> Result<Rc<Connection>, Error> {
        let mut entry = self.dial(host)?;
        let outcome = entry
            .wait_for(|outcome| outcome.is_some())
            .await
            .map_err(|_| Error::Transport("dial task exited without a result".into()))?
            .clone()
            .expect("wait_for returned a settled outcome");
        outcome.map_err(Error::Transport)
    }

    /// Returns the host's pool entry, starting a dial if the host has none.
    fn dial(&self, host: &HostEndpoint) -> Result<PoolEntry, Error> {
        let key = host.public_key;
        if let Some(entry) = self.pool.borrow().get(&key) {
            return Ok(entry.clone());
        }
        let addresses: Vec<String> = host
            .addresses
            .iter()
            .filter(|addr| addr.protocol == Protocol::QUIC)
            .map(|addr| addr.address.clone())
            .collect();
        if addresses.is_empty() {
            return Err(Error::Transport(format!(
                "no QUIC/WebTransport address for host {key}"
            )));
        }

        let (tx, rx) = watch::channel(None);
        self.pool.borrow_mut().insert(key, rx.clone());
        let client = self.clone();
        let entry = rx.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let result = client.dial_addresses(&addresses).await;
            match &result {
                Ok(conn) => client.watch_closed(key, conn),
                Err(e) => {
                    debug!("[WT] dial of host {key} failed: {e}");
                    client.evict(&key, &entry);
                }
            }
            let _ = tx.send(Some(result.map_err(|e| e.to_string())));
        });
        Ok(rx)
    }

    /// Connects to the first address that accepts a WebTransport session.
    async fn dial_addresses(&self, addresses: &[String]) -> Result<Rc<Connection>, Error> {
        let _permit = self
            .dial_sema
            .acquire()
            .await
            .map_err(|e| Error::Transport(format!("dial semaphore closed: {e}")))?;
        let mut last_err = None;
        for addr in addresses {
            let result = timeout(CONNECT_TIMEOUT, connect(addr))
                .await
                .unwrap_or_else(|_| Err(Error::Transport("WebTransport connect: timeout".into())));
            match result {
                Ok(conn) => return Ok(Rc::new(conn)),
                Err(e) => {
                    debug!("[WT] connect to {addr} failed: {e}");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.expect("at least one address was tried"))
    }

    /// Evicts the host once its session's `closed` promise settles.
    fn watch_closed(&self, key: PublicKey, conn: &Rc<Connection>) {
        let closed = conn.transport.closed();
        let conn = Rc::downgrade(conn);
        let pool = Rc::downgrade(&self.pool);
        wasm_bindgen_futures::spawn_local(async move {
            let _ = JsFuture::from(closed).await;
            let Some(pool) = Weak::upgrade(&pool) else {
                return;
            };
            let is_current = pool.borrow().get(&key).is_some_and(|entry| {
                matches!(&*entry.borrow(), Some(Ok(pooled)) if conn.ptr_eq(&Rc::downgrade(pooled)))
            });
            if is_current {
                debug!("[WT] session to host {key} closed; evicting");
                pool.borrow_mut().remove(&key);
            }
        });
    }

    /// Removes the host's entry if it is still `entry`.
    fn evict(&self, key: &PublicKey, entry: &PoolEntry) {
        let mut pool = self.pool.borrow_mut();
        if pool
            .get(key)
            .is_some_and(|current| current.same_channel(entry))
        {
            pool.remove(key);
        }
    }
}

// RPC writes: encode request into a Vec<u8> (instant — Vec impls AsyncWrite),
// then send the whole buffer with write_all_async in one JS Promise.
//
// RPC reads: use AsyncRead on Stream directly. The JS reader.read() already
// returns large chunks from the network buffer, which Stream keeps a view of
// in self.leftover and serves to subsequent poll_read calls without further
// JS calls.
impl Transport for Client {
    async fn host_prices(&self, host: &HostEndpoint) -> Result<(HostPrices, Duration), Error> {
        let conn = self.connection(host).await?;
        let mut stream = conn.open_stream().await?;
        let mut buf = Vec::new();
        let req = RPCSettings::send_request(&mut buf).await?;
        let start = Instant::now();
        stream.write_all_async(&buf).await?;
        let resp = req.complete(&mut stream).await?;
        Ok((resp.settings.prices, start.elapsed()))
    }

    async fn write_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        data: Bytes,
    ) -> Result<(Hash256, Duration), Error> {
        let token = AccountToken::new(account_key, host.public_key);
        let conn = self.connection(host).await?;
        let mut stream = conn.open_stream().await?;
        let mut buf = Vec::new();
        let req = RPCWriteSector::send_request(&mut buf, prices, token, data.clone()).await?;
        let start = Instant::now();
        stream.write_all_async(&buf).await?;
        let resp = req.complete(&mut stream).await?;
        Ok((resp.root, start.elapsed()))
    }

    async fn read_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        token: AccountToken,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<(Bytes, Duration), Error> {
        let conn = self.connection(host).await?;
        let mut stream = conn.open_stream().await?;
        let mut buf = Vec::new();
        let req =
            RPCReadSector::send_request(&mut buf, prices, token, root, offset, length).await?;
        let start = Instant::now();
        stream.write_all_async(&buf).await?;
        let resp = req.complete(&mut stream).await?;
        Ok((resp.data, start.elapsed()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use js_sys::Uint8Array;
    use tokio::io::AsyncReadExt;
    use wasm_bindgen_futures::spawn_local;
    use wasm_bindgen_test::*;

    /// Creates a Stream backed by separate read/write TransformStreams.
    /// Returns (stream, feeder_for_reads, reader_for_writes).
    fn test_stream() -> (
        Stream,
        web_sys::WritableStreamDefaultWriter,
        web_sys::ReadableStreamDefaultReader,
    ) {
        // Read side: feeder → TransformStream → Stream.reader
        let read_ts = web_sys::TransformStream::new().unwrap();
        let stream_reader = read_ts
            .readable()
            .get_reader()
            .unchecked_into::<web_sys::ReadableStreamDefaultReader>();
        let feeder = read_ts.writable().get_writer().unwrap();

        // Write side: Stream.writer → TransformStream → out_reader
        let write_ts = web_sys::TransformStream::new().unwrap();
        let stream_writer = write_ts.writable().get_writer().unwrap();
        let out_reader = write_ts
            .readable()
            .get_reader()
            .unchecked_into::<web_sys::ReadableStreamDefaultReader>();

        (
            Stream::new(stream_reader, stream_writer),
            feeder,
            out_reader,
        )
    }

    /// Feed data into a WritableStreamDefaultWriter from a spawned microtask.
    /// The write and read proceed as separate tasks on the JS event loop,
    /// avoiding deadlock in single-threaded WASM.
    fn feed_async(feeder: web_sys::WritableStreamDefaultWriter, data: Vec<u8>) {
        spawn_local(async move {
            let array = Uint8Array::new_with_length(data.len() as u32);
            array.copy_from(&data);
            JsFuture::from(feeder.write_with_chunk(&array))
                .await
                .unwrap();
        });
    }

    #[wasm_bindgen_test]
    async fn test_stream_write_basic() {
        let (stream, _, out_reader) = test_stream();

        // Write from a spawned task — even with separate TransformStreams,
        // the write-side transform won't pull unless the readable side is
        // being consumed. Spawning lets the read and write interleave.
        let data = b"hello from rust";
        let data_clone = data.to_vec();
        spawn_local(async move {
            stream.write_all_async(&data_clone).await.unwrap();
        });

        let result = JsFuture::from(out_reader.read()).await.unwrap();
        let chunk: ReadableStreamReadResult = result.unchecked_into();
        assert!(!chunk.is_done());
        let received = Uint8Array::new(&chunk.value()).to_vec();
        assert_eq!(received, data);
    }

    #[wasm_bindgen_test]
    async fn test_stream_write_large() {
        let (stream, _, out_reader) = test_stream();

        let data = vec![0xABu8; 4096];
        let data_clone = data.clone();
        spawn_local(async move {
            stream.write_all_async(&data_clone).await.unwrap();
        });

        let mut received = Vec::new();
        while received.len() < data.len() {
            let result = JsFuture::from(out_reader.read()).await.unwrap();
            let chunk: ReadableStreamReadResult = result.unchecked_into();
            assert!(!chunk.is_done());
            received.extend_from_slice(&Uint8Array::new(&chunk.value()).to_vec());
        }
        assert_eq!(received, data);
    }

    #[wasm_bindgen_test]
    async fn test_stream_read_exact() {
        let (mut stream, feeder, _) = test_stream();
        feed_async(feeder, b"hello, world!".to_vec());

        let mut buf = vec![0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        let mut buf = vec![0u8; 8];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b", world!");
    }

    #[wasm_bindgen_test]
    async fn test_stream_read_buffering() {
        let (mut stream, feeder, _) = test_stream();
        feed_async(feeder, vec![42u8; 1024]);

        let mut total = Vec::new();
        for _ in 0..4 {
            let mut buf = vec![0u8; 256];
            stream.read_exact(&mut buf).await.unwrap();
            total.extend_from_slice(&buf);
        }
        assert_eq!(total, vec![42u8; 1024]);
    }

    #[wasm_bindgen_test]
    async fn test_stream_roundtrip() {
        // Use two separate TransformStreams: one for write, one for read.
        // Write side: our Stream writes → write_ts → out_reader verifies
        // Read side: feeder feeds → read_ts → our Stream reads
        let (mut stream, feeder, out_reader) = test_stream();

        let data = b"roundtrip test data!";

        // 1. Feed data into the read side and read it through our Stream
        feed_async(feeder, data.to_vec());
        let mut buf = vec![0u8; data.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, data);

        // 2. Write data through our Stream and verify it on the write side
        let data_vec = data.to_vec();
        spawn_local(async move {
            stream.write_all_async(&data_vec).await.unwrap();
        });
        let result = JsFuture::from(out_reader.read()).await.unwrap();
        let chunk: ReadableStreamReadResult = result.unchecked_into();
        assert!(!chunk.is_done());
        let received = Uint8Array::new(&chunk.value()).to_vec();
        assert_eq!(received, data);
    }

    #[wasm_bindgen_test]
    async fn test_stream_read_multiple_feeds() {
        let (mut stream, feeder, _) = test_stream();

        spawn_local(async move {
            let array = Uint8Array::new_with_length(5);
            array.copy_from(b"hello");
            JsFuture::from(feeder.write_with_chunk(&array))
                .await
                .unwrap();

            let array = Uint8Array::new_with_length(5);
            array.copy_from(b"world");
            JsFuture::from(feeder.write_with_chunk(&array))
                .await
                .unwrap();
        });

        let mut buf = vec![0u8; 10];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"helloworld");
    }
}
