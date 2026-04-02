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
use std::rc::Rc;
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
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

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
        let bidi: web_sys::WebTransportBidirectionalStream =
            JsFuture::from(self.transport.create_bidirectional_stream())
                .await
                .map_err(|e| Error::Transport(format!("createBidirectionalStream: {e:?}")))?
                .unchecked_into();
        let reader = bidi
            .readable()
            .get_reader()
            .unchecked_into::<web_sys::ReadableStreamDefaultReader>();
        let writer = bidi
            .writable()
            .get_writer()
            .map_err(|e| Error::Transport(format!("get_writer: {e:?}")))?;
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
    let wt = web_sys::WebTransport::new_with_options(&url, &options)
        .map_err(|e| Error::Transport(format!("WebTransport constructor: {e:?}")))?;

    let conn = Connection { transport: wt };
    JsFuture::from(conn.transport.ready())
        .await
        .map_err(|e| Error::Transport(format!("WebTransport ready: {e:?}")))?;

    debug!("[WT] connected to {url}");
    Ok(conn)
}

// --- Stream ---

struct Stream {
    reader: web_sys::ReadableStreamDefaultReader,
    pending_read: Option<JsFuture>,
    buf: Vec<u8>,
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
            buf: Vec::new(),
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
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        Ok(())
    }
}

/// AsyncRead for reading RPC responses. The JS `reader.read()` returns
/// large chunks naturally, which are buffered in `self.buf`. Writes bypass
/// poll entirely via write_all_async.
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if !this.buf.is_empty() {
            let n = this.buf.len().min(buf.remaining());
            buf.put_slice(&this.buf[..n]);
            this.buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        if this.pending_read.is_none() {
            this.pending_read = Some(JsFuture::from(this.reader.read()));
        }

        let future = this.pending_read.as_mut().unwrap();
        let result = std::task::ready!(Pin::new(future).poll(cx))
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        this.pending_read = None;

        let chunk: ReadableStreamReadResult = result.unchecked_into();
        if chunk.is_done() {
            return Poll::Ready(Ok(()));
        }

        let data = Uint8Array::new(&chunk.value()).to_vec();
        let n = data.len().min(buf.remaining());
        buf.put_slice(&data[..n]);
        if n < data.len() {
            this.buf = data[n..].to_vec();
        }

        Poll::Ready(Ok(()))
    }
}

// --- Client with connection pooling ---

#[derive(Clone)]
pub struct Client {
    pool: Rc<RefCell<HashMap<PublicKey, Rc<Connection>>>>,
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
        }
    }

    /// Get a pooled connection or create a new one. If a pooled connection
    /// turns out to be stale, the RPC method will call [`evict`] and the
    /// next call will establish a fresh connection.
    async fn connection(&self, host: &HostEndpoint) -> Result<Rc<Connection>, Error> {
        if let Some(conn) = self.pool.borrow().get(&host.public_key).cloned() {
            return Ok(conn);
        }

        // Connect to first available QUIC address
        let mut last_err = None;
        for addr in &host.addresses {
            if addr.protocol != Protocol::QUIC {
                continue;
            }
            match connect(&addr.address).await {
                Ok(conn) => {
                    let conn = Rc::new(conn);
                    self.pool.borrow_mut().insert(host.public_key, conn.clone());
                    return Ok(conn);
                }
                Err(e) => {
                    debug!("[WT] connect to {} failed: {e}", addr.address);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            Error::Transport(format!(
                "no QUIC/WebTransport address for host {}",
                host.public_key
            ))
        }))
    }

    fn evict(&self, host_key: &PublicKey) {
        self.pool.borrow_mut().remove(host_key);
    }

    /// Returns true if the error indicates the connection is broken and
    /// should be evicted from the pool. Transport and I/O errors mean the
    /// session is dead; RPC-level errors (e.g. insufficient funds) are
    /// application errors on an otherwise healthy connection.
    fn should_evict(err: &Error) -> bool {
        matches!(err, Error::Transport(_) | Error::Io(_))
    }
}

// RPC writes: encode request into a Vec<u8> (instant — Vec impls AsyncWrite),
// then send the whole buffer with write_all_async in one JS Promise.
//
// RPC reads: use AsyncRead on Stream directly. The JS reader.read() already
// returns large chunks from the network buffer, which Stream stores in
// self.buf and serves to subsequent poll_read calls without further JS calls.
impl Transport for Client {
    async fn host_prices(&self, host: &HostEndpoint) -> Result<HostPrices, Error> {
        let conn = self.connection(host).await?;
        let result: Result<HostPrices, Error> = async {
            let mut stream = conn.open_stream().await?;
            let mut buf = Vec::new();
            let req = RPCSettings::send_request(&mut buf).await?;
            stream.write_all_async(&buf).await?;
            let resp = req.complete(&mut stream).await?;
            Ok(resp.settings.prices)
        }
        .await;
        if let Err(e) = &result
            && Self::should_evict(e)
        {
            self.evict(&host.public_key);
        }
        result
    }

    async fn write_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        data: Bytes,
    ) -> Result<Hash256, Error> {
        let token = AccountToken::new(account_key, host.public_key);
        let conn = self.connection(host).await?;
        let result: Result<Hash256, Error> = async {
            let mut stream = conn.open_stream().await?;
            let mut buf = Vec::new();
            let req = RPCWriteSector::send_request(&mut buf, prices, token, data.clone()).await?;
            stream.write_all_async(&buf).await?;
            let resp = req.complete(&mut stream).await?;
            Ok(resp.root)
        }
        .await;
        if let Err(e) = &result
            && Self::should_evict(e)
        {
            self.evict(&host.public_key);
        }
        result
    }

    async fn read_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, Error> {
        let token = AccountToken::new(account_key, host.public_key);
        let conn = self.connection(host).await?;
        let result: Result<Bytes, Error> = async {
            let mut stream = conn.open_stream().await?;
            let mut buf = Vec::new();
            let req =
                RPCReadSector::send_request(&mut buf, prices, token, root, offset, length).await?;
            stream.write_all_async(&buf).await?;
            let resp = req.complete(&mut stream).await?;
            Ok(resp.data)
        }
        .await;
        if let Err(e) = &result
            && Self::should_evict(e)
        {
            self.evict(&host.public_key);
        }
        result
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
