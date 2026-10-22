//! WebTransport-based RHP4 client for WASM targets.
//!
//! Provides a [`Client`] that performs RHP4 RPCs using the
//! browser's WebTransport API, mirroring the siamux client on native.
//! Connections are pooled per host — one WebTransport session per host,
//! with multiple bidirectional streams for concurrent RPCs.
//!
//! Writes use bounded chunks and direct `JsFuture` calls to avoid tokio
//! poll overhead. Reads use `AsyncRead` — the JS `reader.read()` already
//! returns large chunks which are buffered internally.

use crate::client::Metrics;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Range;
use std::rc::{Rc, Weak};
use std::sync::Arc;

use bytes::Bytes;
use log::debug;
use sia_core::rhp4::protocol::{RPCReadSector, RPCSettings, RPCWriteSector};
use sia_core::rhp4::{AccountToken, HostPrices};
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;
use sia_core::types::v2::Protocol;
use tokio::sync::{Semaphore, watch};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::time::{Duration, Instant, timeout};

use super::dial_failures::DialFailures;
use super::{Error, HostEndpoint};
use crate::tokens::AccountTokenSource;

mod stream;
use stream::{Stream, open_bidi_stream};

/// The WebTransport URL path for the RHP4 protocol.
const RHP4_PATH: &str = "/sia/rhp/v4";

/// Maximum concurrent in-flight dials.
const MAX_PENDING_CONNS: usize = 4;

/// Timeout for establishing a WebTransport session to one address.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

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
    async fn open_stream(&self, metrics: Arc<Metrics>, host: PublicKey) -> Result<Stream, Error> {
        open_bidi_stream(self.transport.create_bidirectional_stream(), metrics, host).await
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
        Error::DialRefused(format!("WebTransport constructor: {}", js_err_message(&e)))
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
        .map_err(|e| Error::DialRefused(format!("WebTransport ready: {}", js_err_message(&e))))?;

    debug!("[WT] connected to {url}");
    Ok(conn)
}

// --- Client with connection pooling ---

/// `None` while the dial is in flight.
type DialOutcome = Option<Result<Rc<Connection>, String>>;

type PoolEntry = watch::Receiver<DialOutcome>;

#[derive(Clone)]
pub struct Client {
    pool: Rc<RefCell<HashMap<PublicKey, PoolEntry>>>,
    dial_sema: Rc<Semaphore>,
    failures: Rc<RefCell<DialFailures>>,
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
            failures: Rc::new(RefCell::new(DialFailures::default())),
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
        let now = Instant::now();
        let addresses: Vec<String> = {
            let mut failures = self.failures.borrow_mut();
            addresses
                .into_iter()
                .filter(|addr| !failures.in_backoff(addr, now))
                .collect()
        };
        if addresses.is_empty() {
            return Err(Error::DialRefused(format!(
                "every address of host {key} refused a handshake in the last five minutes"
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
            // Checked again here, after waiting for a dial slot, for an address
            // listed twice or refused while this dial waited.
            if self.failures.borrow_mut().in_backoff(addr, Instant::now()) {
                last_err = Some(Error::DialRefused(format!(
                    "{addr} refused a handshake in the last five minutes"
                )));
                continue;
            }
            // A timeout is not recorded. Chrome can hold a healthy host back
            // for up to a minute while it is counting earlier failures.
            let result = timeout(CONNECT_TIMEOUT, connect(addr))
                .await
                .unwrap_or_else(|_| Err(Error::Transport("WebTransport connect: timeout".into())));
            match result {
                Ok(conn) => return Ok(Rc::new(conn)),
                Err(e) => {
                    debug!("[WT] connect to {addr} failed: {e}");
                    if matches!(e, Error::DialRefused(_)) {
                        self.failures.borrow_mut().record(addr, Instant::now());
                    }
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
// then send bounded chunks, awaiting each JS Promise for backpressure.
//
// RPC reads: use AsyncRead on Stream directly. The JS reader.read() already
// returns large chunks from the network buffer, which Stream keeps a view of
// in self.leftover and serves to subsequent poll_read calls without further
// JS calls.
impl Client {
    async fn host_stream(
        &self,
        host: &HostEndpoint,
        metrics: Arc<Metrics>,
    ) -> Result<Stream, Error> {
        let result = async {
            let conn = self.connection(host).await?;
            conn.open_stream(metrics.clone(), host.public_key).await
        }
        .await;
        match result {
            Ok(stream) => Ok(stream),
            Err(err) => metrics.record_result(host.public_key, Err(err)),
        }
    }

    pub(crate) async fn host_prices(
        &self,
        host: &HostEndpoint,
        metrics: Arc<Metrics>,
    ) -> Result<HostPrices, Error> {
        self.host_stream(host, metrics)
            .await?
            .run(async |stream| {
                let mut buf = Vec::new();
                let req = RPCSettings::send_request(&mut buf).await?;
                stream.write_chunks(&buf).await?;
                let resp = req.complete(stream).await?;
                Ok(resp.settings.prices)
            })
            .await
    }

    pub(crate) async fn write_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        data: Bytes,
        metrics: Arc<Metrics>,
    ) -> Result<Hash256, Error> {
        let token = AccountToken::new(account_key, host.public_key);
        self.host_stream(host, metrics)
            .await?
            .run(async |stream| {
                let mut buf = Vec::new();
                let req = RPCWriteSector::send_request(&mut buf, prices, token, data).await?;
                stream.write_chunks(&buf).await?;
                let resp = req.complete(stream).await?;
                Ok(resp.root)
            })
            .await
    }

    pub(crate) async fn read_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        tokens: &AccountTokenSource,
        root: Hash256,
        range: Range<usize>,
        metrics: Arc<Metrics>,
    ) -> Result<Bytes, Error> {
        self.host_stream(host, metrics)
            .await?
            .run(async |stream| {
                let token = tokens
                    .token(host.public_key)
                    .map_err(|_| Error::NoToken(host.public_key))?;
                let mut buf = Vec::new();
                let req = RPCReadSector::send_request(
                    &mut buf,
                    prices,
                    token,
                    root,
                    range.start,
                    range.len(),
                )
                .await?;
                stream.write_chunks(&buf).await?;
                let resp = req.complete(stream).await?;
                Ok(resp.data)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Instant;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    async fn test_refused_address_is_not_dialed_again() {
        // The space makes the URL invalid, so the browser rejects the session at once.
        let address = "not a host:9984";
        let host = HostEndpoint {
            public_key: PrivateKey::from_seed(&[1u8; 32]).public_key(),
            addresses: vec![sia_core::types::v2::NetAddress {
                protocol: Protocol::QUIC,
                address: address.to_string(),
            }],
        };
        let client = Client::new();

        assert!(client.connection(&host).await.is_err());
        assert!(
            client
                .failures
                .borrow_mut()
                .in_backoff(address, Instant::now())
        );
        match client.dial(&host) {
            Err(Error::DialRefused(_)) => {}
            Err(e) => panic!("expected DialRefused, got {e}"),
            Ok(_) => panic!("the refused address was dialed again"),
        }
    }

    #[wasm_bindgen_test]
    async fn test_address_listed_twice_is_dialed_once() {
        let address = "not a host either:9984";
        let quic = || sia_core::types::v2::NetAddress {
            protocol: Protocol::QUIC,
            address: address.to_string(),
        };
        let host = HostEndpoint {
            public_key: PrivateKey::from_seed(&[2u8; 32]).public_key(),
            addresses: vec![quic(), quic()],
        };
        let client = Client::new();

        // The second copy is skipped once the first is refused, so the error is the skip's.
        let err = client
            .connection(&host)
            .await
            .err()
            .expect("the dial fails");
        assert!(
            err.to_string().contains("in the last five minutes"),
            "the second copy was dialed: {err}"
        );
    }

    #[wasm_bindgen_test]
    async fn stream_open_failure_is_recorded_once() {
        let client = Client::new();
        let host = HostEndpoint {
            public_key: PublicKey::new([1; 32]),
            addresses: vec![],
        };
        let metrics = Arc::new(Metrics::default());
        metrics.record_result(host.public_key, Ok(())).unwrap();
        assert!(client.host_prices(&host, metrics.clone()).await.is_err());
        assert_eq!(metrics.failure_rate(host.public_key), 20);
    }
}
