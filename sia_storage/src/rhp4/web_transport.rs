use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use js_sys::{Reflect, Uint8Array};
use log::debug;
use sia_core::encoding_async::{AsyncDecoder, AsyncEncoder};
use sia_core::rhp4::{
    self, AccountToken, HostPrices, RPCReadSector, RPCSettings, RPCWriteSector, Transport,
};
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::v2::Protocol;
use sia_core::types::{Currency, Hash256};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{ReadableStreamDefaultReader, WritableStreamDefaultWriter};

use sia_core::rhp4::HostSettings;

use crate::hosts::Hosts;
use crate::rhp4::{Error, Transport as RHP4Client};

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
    async fn write_all(&mut self, data: &[u8]) -> Result<(), Error> {
        let array = Uint8Array::from(data);
        JsFuture::from(self.writer.write_with_chunk(&array))
            .await
            .map_err(|e| Error::Transport(format!("write error: {:?}", e)))?;
        Ok(())
    }
}

impl AsyncEncoder for Stream {
    type Error = Error;

    async fn encode_buf(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.write_all(buf).await
    }
}

impl AsyncDecoder for Stream {
    type Error = Error;

    async fn decode_buf(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.read_exact(buf).await
    }
}

impl Transport for Stream {
    type Error = Error;

    async fn write_request<R: rhp::RPCRequest>(&mut self, req: &R) -> Result<(), Self::Error> {
        req.encode_request(self).await?;
        Ok(())
    }

    async fn write_bytes(&mut self, data: Bytes) -> Result<(), Self::Error> {
        self.write_all(&data).await
    }

    async fn read_response<R: rhp::RPCResponse>(&mut self) -> Result<R, Self::Error> {
        R::decode_response(self).await
    }

    async fn write_response<RR: rhp::RPCResponse>(&mut self, resp: &RR) -> Result<(), Self::Error> {
        resp.encode_response(self).await?;
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
    let stream = conn.open_stream().await?;
    let resp = RPCSettings::send_request(stream).await?.complete().await?;
    Ok(resp.settings)
}

#[derive(Clone, Debug)]
pub struct Client {
    hosts: Hosts,
    cached_prices: Arc<RwLock<HashMap<PublicKey, HostPrices>>>,
    cached_tokens: Arc<RwLock<HashMap<PublicKey, AccountToken>>>,
    connection_pool: Arc<RwLock<HashMap<PublicKey, Arc<Connection>>>>,
}

impl Client {
    pub fn new(hosts: Hosts) -> Client {
        Client {
            hosts,
            cached_prices: Arc::new(RwLock::new(HashMap::new())),
            cached_tokens: Arc::new(RwLock::new(HashMap::new())),
            connection_pool: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn evict_connection(&self, host_key: &PublicKey) {
        self.connection_pool
            .write()
            .expect("WASM is single-threaded; lock cannot be poisoned")
            .remove(host_key);
    }

    fn evict_prices(&self, host_key: &PublicKey) {
        self.cached_prices
            .write()
            .expect("WASM is single-threaded; lock cannot be poisoned")
            .remove(host_key);
    }

    fn get_cached_prices(&self, host_key: &PublicKey) -> Option<HostPrices> {
        let cache = self
            .cached_prices
            .read()
            .expect("WASM is single-threaded; lock cannot be poisoned");
        match cache.get(host_key) {
            Some(prices) if prices.valid_until > Utc::now() => Some(prices.clone()),
            _ => None,
        }
    }

    fn set_cached_prices(&self, host_key: &PublicKey, prices: HostPrices) {
        self.cached_prices
            .write()
            .expect("WASM is single-threaded; lock cannot be poisoned")
            .insert(*host_key, prices);
    }

    fn account_token(&self, account_key: &PrivateKey, host_key: PublicKey) -> AccountToken {
        let cached = {
            let cache = self
                .cached_tokens
                .read()
                .expect("WASM is single-threaded; lock cannot be poisoned");
            cache.get(&host_key).cloned()
        };
        match cached {
            Some(token) if token.valid_until > Utc::now() => token,
            _ => {
                let token = AccountToken::new(account_key, host_key);
                self.cached_tokens
                    .write()
                    .expect("WASM is single-threaded; lock cannot be poisoned")
                    .insert(host_key, token.clone());
                token
            }
        }
    }

    async fn host_connection(&self, host_key: PublicKey) -> Result<Arc<Connection>, Error> {
        // Check pool first
        if let Some(conn) = self
            .connection_pool
            .read()
            .expect("WASM is single-threaded; lock cannot be poisoned")
            .get(&host_key)
            .cloned()
        {
            return Ok(conn);
        }

        // No pooled connection — create new one
        let addresses = self
            .hosts
            .addresses(&host_key)
            .ok_or_else(|| Error::Transport(format!("unknown host: {host_key}")))?;

        let mut last_err = None;
        for addr in addresses {
            if addr.protocol != Protocol::QUIC {
                continue;
            }

            match connect(&addr.address).await {
                Ok(conn) => {
                    let conn = Arc::new(conn);
                    self.connection_pool
                        .write()
                        .expect("WASM is single-threaded; lock cannot be poisoned")
                        .insert(host_key, conn.clone());
                    return Ok(conn);
                }
                Err(e) => {
                    debug!(
                        "host_connection({host_key}): connect to {} failed: {e}",
                        addr.address
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            Error::Transport(format!(
                "no QUIC/WebTransport address found for host {host_key}"
            ))
        }))
    }

    /// Fetches host prices, either from cache or by running the settings
    /// RPC on the provided connection. This avoids opening a second
    /// WebTransport session just for the price fetch.
    async fn get_or_fetch_prices(
        &self,
        host_key: &PublicKey,
        conn: &Connection,
        refresh: bool,
    ) -> Result<HostPrices, Error> {
        if !refresh {
            if let Some(prices) = self.get_cached_prices(host_key) {
                debug!("get_or_fetch_prices: using cached prices for {host_key}");
                return Ok(prices);
            }
        }

        debug!("get_or_fetch_prices: fetching prices from {host_key}");
        let stream = conn.open_stream().await?;
        let resp = RPCSettings::send_request(stream).await?.complete().await?;
        self.set_cached_prices(host_key, resp.settings.prices.clone());
        Ok(resp.settings.prices)
    }
}

#[async_trait(?Send)]
impl RHP4Client for Client {
    async fn host_prices(&self, host_key: PublicKey, refresh: bool) -> Result<HostPrices, Error> {
        if !refresh {
            if let Some(prices) = self.get_cached_prices(&host_key) {
                debug!("host_prices: using cached prices for {host_key}");
                return Ok(prices);
            }
        }

        debug!("host_prices: fetching prices from {host_key}");
        let conn = self.host_connection(host_key).await?;
        let result: Result<HostPrices, Error> = async {
            let stream = conn.open_stream().await?;
            let resp = RPCSettings::send_request(stream).await?.complete().await?;
            debug!("host_prices: got prices from {host_key}");
            self.set_cached_prices(&host_key, resp.settings.prices.clone());
            Ok(resp.settings.prices)
        }
        .await;
        if result.is_err() {
            self.evict_connection(&host_key);
        }
        result
    }

    async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> Result<Hash256, Error> {
        let conn = self.host_connection(host_key).await?;
        let result: Result<Hash256, Error> = async {
            let prices = self.get_or_fetch_prices(&host_key, &conn, false).await?;
            let stream = conn.open_stream().await?;
            let token = self.account_token(account_key, host_key);
            debug!("write_sector: sending {} bytes to {host_key}", sector.len());
            let resp = RPCWriteSector::send_request(stream, prices, token, sector)
                .await?
                .complete()
                .await?;
            debug!("write_sector: completed for {host_key}");
            Ok(resp.root)
        }
        .await;
        if result.is_err() {
            self.evict_connection(&host_key);
            self.evict_prices(&host_key);
        }
        result
    }

    async fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, Error> {
        let conn = self.host_connection(host_key).await?;
        let result: Result<Bytes, Error> = async {
            let prices = self.get_or_fetch_prices(&host_key, &conn, false).await?;
            let stream = conn.open_stream().await?;
            let token = self.account_token(account_key, host_key);
            let resp = RPCReadSector::send_request(stream, prices, token, root, offset, length)
                .await?
                .complete()
                .await?;
            Ok(resp.data)
        }
        .await;
        if result.is_err() {
            self.evict_connection(&host_key);
            self.evict_prices(&host_key);
        }
        result
    }
}
