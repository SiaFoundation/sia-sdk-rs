use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use js_sys::{Reflect, Uint8Array};
use log::debug;
use sia_core::rhp4::protocol::{RPCReadSector, RPCSettings, RPCWriteSector};
use sia_core::rhp4::{AccountToken, HostPrices};
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;
use sia_core::types::v2::Protocol;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{ReadableStreamDefaultReader, WritableStreamDefaultWriter};

use sia_core::rhp4::HostSettings;

use super::{Error, HostEndpoint, Transport};

/// A WebTransport connection to a host. Supports opening multiple
/// bidirectional streams for sequential RPCs without reconnecting.
#[derive(Debug)]
struct Connection {
    transport: web_sys::WebTransport,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.transport.close();
    }
}

impl Connection {
    /// Opens a new bidirectional stream on this connection.
    async fn open_stream(&self) -> Result<Stream, Error> {
        let bidi_stream = JsFuture::from(self.transport.create_bidirectional_stream())
            .await
            .map_err(|e| Error::Transport(format!("createBidirectionalStream error: {:?}", e)))?;

        let bidi = web_sys::WebTransportBidirectionalStream::from(bidi_stream);
        let reader = bidi
            .readable()
            .get_reader()
            .dyn_into::<ReadableStreamDefaultReader>()
            .map_err(|e| Error::Transport(format!("get_reader error: {:?}", e)))?;
        let writer = bidi
            .writable()
            .get_writer()
            .map_err(|e| Error::Transport(format!("get_writer error: {:?}", e)))?;

        Ok(Stream {
            reader,
            writer,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
        })
    }
}

/// A bidirectional stream on a WebTransport connection, used for a
/// single RHP4 RPC. The stream does not own the underlying connection —
/// the [`Connection`] must be kept alive for the stream's lifetime.
struct Stream {
    reader: ReadableStreamDefaultReader,
    writer: WritableStreamDefaultWriter,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let n = std::cmp::min(self.read_buf.len(), buf.remaining());
        buf.put_slice(&self.read_buf[..n]);
        self.read_buf.drain(..n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.write_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Actual flush to JS WritableStream happens via flush_write_buf()
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream {
    /// Read exactly `buf.len()` bytes from the stream, buffering as needed.
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        let mut filled = 0;
        while filled < buf.len() {
            // drain internal buffer first
            if !self.read_buf.is_empty() {
                let n = std::cmp::min(self.read_buf.len(), buf.len() - filled);
                buf[filled..filled + n].copy_from_slice(&self.read_buf[..n]);
                self.read_buf.drain(..n);
                filled += n;
                continue;
            }

            // read a chunk from the JS ReadableStream
            let result = JsFuture::from(self.reader.read())
                .await
                .map_err(|e| Error::Transport(format!("read error: {:?}", e)))?;

            let done = Reflect::get(&result, &JsValue::from_str("done"))
                .map_err(|e| Error::Transport(format!("reflect error: {:?}", e)))?
                .as_bool()
                .unwrap_or(true);

            if done {
                return Err(Error::Transport("stream closed unexpectedly".into()));
            }

            let value = Reflect::get(&result, &JsValue::from_str("value"))
                .map_err(|e| Error::Transport(format!("reflect error: {:?}", e)))?;

            let chunk = Uint8Array::new(&value);
            let mut data = vec![0u8; chunk.length() as usize];
            chunk.copy_to(&mut data);
            self.read_buf.extend_from_slice(&data);
        }
        Ok(())
    }

    /// Write all bytes to the JS WritableStream.
    async fn write_all_js(&mut self, data: &[u8]) -> Result<(), Error> {
        let array = Uint8Array::from(data);
        JsFuture::from(self.writer.write_with_chunk(&array))
            .await
            .map_err(|e| Error::Transport(format!("write error: {:?}", e)))?;
        Ok(())
    }

    /// Flush the internal write buffer to the JS WritableStream.
    async fn flush_write_buf(&mut self) -> Result<(), Error> {
        if !self.write_buf.is_empty() {
            let buf = std::mem::take(&mut self.write_buf);
            self.write_all_js(&buf).await?;
        }
        Ok(())
    }
}

/// The WebTransport URL path for the RHP4 protocol.
const RHP4_PATH: &str = "/sia/rhp/v4";

/// Opens a WebTransport connection to the given address. The connection
/// can be used to open multiple bidirectional streams via
/// [`Connection::open_stream`].
async fn connect(address: &str) -> Result<Connection, Error> {
    let url = if address.starts_with("https://") {
        address.to_string()
    } else if address.contains('/') {
        // Already has a path component (e.g. host:port/sia/rhp/v4)
        format!("https://{address}")
    } else {
        // Bare host:port — append the RHP4 path
        format!("https://{address}{RHP4_PATH}")
    };
    debug!("[WT] connecting to {url}");

    let options = web_sys::WebTransportOptions::new();
    let wt = web_sys::WebTransport::new_with_options(&url, &options)
        .map_err(|e| Error::Transport(format!("WebTransport constructor error: {:?}", e)))?;

    // Wrap immediately so .close() is called if ready() fails or
    // the future is cancelled (e.g. by a timeout in tokio::select!).
    let conn = Connection { transport: wt };
    let ready_promise = conn.transport.ready();

    match JsFuture::from(ready_promise).await {
        Ok(_) => {
            debug!("[WT] connected to {url}");
            Ok(conn)
        }
        Err(e) => {
            debug!("[WT] ready failed for {url}: {:?}", e);
            Err(Error::Transport(format!(
                "WebTransport ready error: {:?}",
                e
            )))
        }
    }
}

/// Connects to a host at the given address via WebTransport and fetches
/// its settings using the RHP4 settings RPC.
pub async fn fetch_host_settings(address: &str) -> Result<HostSettings, Error> {
    let conn = connect(address).await?;
    let mut stream = conn.open_stream().await?;
    let pending = RPCSettings::send_request(&mut stream).await?;
    stream.flush_write_buf().await?;
    let resp = pending.complete(&mut stream).await?;
    Ok(resp.settings)
}

#[derive(Clone, Debug)]
pub struct Client {
    open_conns: Arc<RwLock<HashMap<PublicKey, Arc<Connection>>>>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Self {
            open_conns: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns a stream to the host, reusing an existing connection
    /// from the pool or creating a new one.
    async fn host_stream(&self, host: &HostEndpoint) -> Result<Stream, Error> {
        // Check pool first
        if let Some(conn) = self
            .open_conns
            .read()
            .expect("WASM is single-threaded; lock cannot be poisoned")
            .get(&host.public_key)
            .cloned()
        {
            match conn.open_stream().await {
                Ok(stream) => return Ok(stream),
                Err(_) => {
                    // Connection is stale, evict and reconnect below
                    self.open_conns
                        .write()
                        .expect("WASM is single-threaded; lock cannot be poisoned")
                        .remove(&host.public_key);
                }
            }
        }

        // No pooled connection — create new one
        let mut last_err = None;
        for addr in &host.addresses {
            if addr.protocol != Protocol::QUIC {
                continue;
            }

            match connect(&addr.address).await {
                Ok(conn) => {
                    let conn = Arc::new(conn);
                    self.open_conns
                        .write()
                        .expect("WASM is single-threaded; lock cannot be poisoned")
                        .insert(host.public_key, conn.clone());
                    return conn.open_stream().await;
                }
                Err(e) => {
                    debug!(
                        "host_stream({}): connect to {} failed: {e}",
                        host.public_key, addr.address
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            Error::Transport(format!(
                "no QUIC/WebTransport address found for host {}",
                host.public_key
            ))
        }))
    }
}

#[async_trait(?Send)]
impl Transport for Client {
    async fn host_prices(&self, host: &HostEndpoint) -> Result<HostPrices, Error> {
        let mut stream = self
            .host_stream(host)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let pending = RPCSettings::send_request(&mut stream).await?;
        stream.flush_write_buf().await?;
        let resp = pending.complete(&mut stream).await?;
        Ok(resp.settings.prices)
    }

    async fn write_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        data: Bytes,
    ) -> Result<Hash256, Error> {
        let token = AccountToken::new(account_key, host.public_key);
        let mut stream = self
            .host_stream(host)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let pending = RPCWriteSector::send_request(&mut stream, prices, token, data).await?;
        stream.flush_write_buf().await?;
        let resp = pending.complete(&mut stream).await?;
        Ok(resp.root)
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
        let mut stream = self
            .host_stream(host)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let pending =
            RPCReadSector::send_request(&mut stream, prices, token, root, offset, length).await?;
        stream.flush_write_buf().await?;
        let resp = pending.complete(&mut stream).await?;
        Ok(resp.data)
    }
}
