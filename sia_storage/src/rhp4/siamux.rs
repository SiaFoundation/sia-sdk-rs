use crate::client::Metrics;
use crate::client::metrics::TransferRate;
use crate::time::{Elapsed, timeout};

use bytes::Bytes;
use core::fmt::Debug;
use ed25519_dalek::{SignatureError, VerifyingKey};
use log::debug;
use std::collections::HashMap;
use std::ops::Range;
use std::sync::{Arc, Mutex, Weak};
use thiserror::{self, Error};
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::watch;

use crate::rhp4::HostEndpoint;
use crate::task::AbortOnDropHandle;
use crate::time::Duration;

use super::Error as TransportError;
use sia_core::rhp4::protocol::{RPCReadSector, RPCSettings, RPCWriteSector};
use sia_core::rhp4::{AccountToken, HostPrices};

use crate::tokens::AccountTokenSource;
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;
use sia_core::types::v2::Protocol;
use sia_mux::{Mux, Stream};

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("connect error: {0}")]
    Io(#[from] std::io::Error),

    #[error("mux dial error: {0}")]
    Dial(#[from] sia_mux::DialError),

    #[error("mux error: {0}")]
    Mux(#[from] sia_mux::MuxError),

    #[error("timeout error: {0}")]
    Elapsed(#[from] Elapsed),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[from] SignatureError),

    #[error("no endpoint")]
    NoEndpoint,
}

/// A connection being established on its own task. Waiters hold the `Arc`;
/// dropping the last one aborts the dial.
struct Dial {
    outcome: watch::Receiver<Option<Result<Arc<Mux>, String>>>,
    _task: AbortOnDropHandle<()>,
}

enum ConnEntry {
    Open(Arc<Mux>),
    Dialing(Weak<Dial>),
}

#[derive(Clone)]
pub struct Client {
    conns: Arc<Mutex<HashMap<PublicKey, ConnEntry>>>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Self {
            conns: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn new_conn(host: &HostEndpoint) -> Result<Mux, ConnectError> {
        let host_bytes: [u8; 32] = host.public_key.into();
        let verifying_key = VerifyingKey::from_bytes(&host_bytes)?;

        for addr in &host.addresses {
            if addr.protocol != Protocol::SiaMux {
                continue;
            }
            let resolved_addrs = lookup_host(addr.address.as_str())
                .await
                .inspect_err(|e| debug!("failed to resolve {}: {e}", addr.address))?;

            for socket in resolved_addrs {
                match TcpStream::connect(socket).await {
                    Ok(tcp) => match sia_mux::dial(tcp, &verifying_key).await {
                        Ok(mux_conn) => {
                            debug!(
                                "established siamux connection to {} via {socket}",
                                host.public_key
                            );
                            return Ok(mux_conn);
                        }
                        Err(e) => {
                            debug!(
                                "mux handshake failed to {} via {socket}: {e}",
                                host.public_key
                            );
                        }
                    },
                    Err(e) => {
                        debug!("TCP connect failed to {} ({socket}): {e}", addr.address);
                    }
                }
            }
        }
        Err(ConnectError::NoEndpoint)
    }

    fn dial(&self, host: &HostEndpoint) -> Arc<Dial> {
        let host = HostEndpoint {
            public_key: host.public_key,
            addresses: host.addresses.clone(),
        };
        let conns = self.conns.clone();
        let (tx, outcome) = watch::channel(None);
        let task = tokio::spawn(async move {
            let result = async {
                let mux = timeout(Duration::from_secs(10), Self::new_conn(&host))
                    .await
                    .inspect_err(|e| {
                        debug!("siamux connection to {} timed out: {e}", host.public_key);
                    })??;
                debug!("created new siamux connection to {}", host.public_key);
                Ok::<_, ConnectError>(Arc::new(mux))
            }
            .await;
            if let Ok(mux) = &result {
                conns
                    .lock()
                    .unwrap()
                    .insert(host.public_key, ConnEntry::Open(mux.clone()));
            }
            let _ = tx.send(Some(result.map_err(|e| e.to_string())));
        });
        Arc::new(Dial {
            outcome,
            _task: AbortOnDropHandle::new(task),
        })
    }

    /// Opens a stream on the host's connection, dialing one if none is open.
    /// Concurrent callers share one dial, which runs until it completes or
    /// none of them waits on it any more.
    async fn host_stream(&self, host: &HostEndpoint) -> Result<Stream, TransportError> {
        let dial = {
            let mut conns = self.conns.lock().unwrap();
            match conns.get(&host.public_key) {
                Some(ConnEntry::Open(mux)) => {
                    return mux.dial_stream().map_err(|e| {
                        conns.remove(&host.public_key);
                        TransportError::Transport(ConnectError::from(e).to_string())
                    });
                }
                // a finished dial still held by its waiters has failed; start over
                Some(ConnEntry::Dialing(dial))
                    if let Some(dial) = dial.upgrade()
                        && dial.outcome.borrow().is_none() =>
                {
                    dial
                }
                _ => {
                    let dial = self.dial(host);
                    conns.insert(host.public_key, ConnEntry::Dialing(Arc::downgrade(&dial)));
                    dial
                }
            }
        };
        let mut outcome = dial.outcome.clone();
        let outcome = outcome
            .wait_for(Option::is_some)
            .await
            .map_err(|_| TransportError::Transport("siamux dial exited".to_string()))?;
        let mux = outcome
            .as_ref()
            .expect("waited for an outcome")
            .clone()
            .map_err(TransportError::Transport)?;
        mux.dial_stream().map_err(|e| {
            self.conns.lock().unwrap().remove(&host.public_key);
            TransportError::Transport(ConnectError::from(e).to_string())
        })
    }
}

/// Wraps a stream and records its result and transfer metrics
struct RpcStream {
    stream: Stream,
    metrics: Arc<Metrics>,
    host: PublicKey,
}

impl RpcStream {
    async fn run<T>(
        mut self,
        rpc: impl AsyncFnOnce(&mut Stream) -> Result<T, TransportError>,
    ) -> Result<T, TransportError> {
        let result = rpc(&mut self.stream).await;
        self.metrics.record_result(self.host, result)
    }
}

impl Drop for RpcStream {
    fn drop(&mut self) {
        let (read_bytes, read_elapsed) = self.stream.read_metric();
        let (write_bytes, write_elapsed) = self.stream.write_metric();
        self.metrics.record_transfer(
            self.host,
            TransferRate::try_new(read_bytes, read_elapsed),
            TransferRate::try_new(write_bytes, write_elapsed),
        );
    }
}

impl Client {
    async fn rpc_stream(
        &self,
        host: &HostEndpoint,
        metrics: Arc<Metrics>,
    ) -> Result<RpcStream, TransportError> {
        match self.host_stream(host).await {
            Ok(mut stream) => {
                stream.set_idle_timeout(Some(super::RPC_IDLE_TIMEOUT));
                Ok(RpcStream {
                    stream,
                    metrics,
                    host: host.public_key,
                })
            }
            Err(err) => metrics.record_result(host.public_key, Err(err)),
        }
    }

    pub(crate) async fn host_prices(
        &self,
        host: &HostEndpoint,
        metrics: Arc<Metrics>,
    ) -> Result<HostPrices, TransportError> {
        self.rpc_stream(host, metrics)
            .await?
            .run(async |stream| {
                let resp = RPCSettings::send_request(stream)
                    .await?
                    .complete(stream)
                    .await?;
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
    ) -> Result<Hash256, TransportError> {
        let token = AccountToken::new(account_key, host.public_key);
        self.rpc_stream(host, metrics)
            .await?
            .run(async |stream| {
                let resp = RPCWriteSector::send_request(stream, prices, token, data)
                    .await?
                    .complete(stream)
                    .await?;
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
    ) -> Result<Bytes, TransportError> {
        self.rpc_stream(host, metrics)
            .await?
            .run(async |stream| {
                let token = tokens
                    .token(host.public_key)
                    .map_err(|_| TransportError::NoToken(host.public_key))?;
                let resp = RPCReadSector::send_request(
                    stream,
                    prices,
                    token,
                    root,
                    range.start,
                    range.len(),
                )
                .await?
                .complete(stream)
                .await?;
                Ok(resp.data)
            })
            .await
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ed25519_dalek::SigningKey;
    use sia_core::types::v2::NetAddress;
    use tokio::net::TcpListener;

    use super::*;
    use crate::time::sleep;

    #[tokio::test(start_paused = true)]
    async fn partial_read_metrics_survive_timeout_and_cancellation() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for cancel in [false, true] {
            let (a, b) = tokio::io::duplex(64 * 1024);
            let (client, server) =
                tokio::join!(sia_mux::dial_anonymous(a), sia_mux::accept_anonymous(b));
            let client = client.unwrap();
            let server = server.unwrap();
            let metrics = Arc::new(Metrics::default());
            let host = PublicKey::new([1; 32]);
            metrics.record_result(host, Ok(())).unwrap();
            let read = RpcStream {
                stream: client.dial_stream().unwrap(),
                metrics: metrics.clone(),
                host,
            }
            .run(async |stream| {
                stream.set_idle_timeout(Some(Duration::from_secs(2)));
                stream.write_all(b"request").await?;
                stream.read_exact(&mut [0; 2]).await?;
                Ok(())
            });
            let peer = async {
                let mut stream = server.accept_stream().await.unwrap();
                sleep(Duration::from_secs(1)).await;
                stream.write_all(b"a").await.unwrap();
                sleep(Duration::from_secs(5)).await;
            };
            let (result, _) = tokio::join!(
                timeout(Duration::from_secs(if cancel { 2 } else { 10 }), read),
                peer,
            );
            if cancel {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().unwrap_err().is_timeout());
            }
            assert_eq!(metrics.failure_rate(host), if cancel { 0 } else { 20 });
            assert_eq!(
                metrics.transfer_rates().read.unwrap(),
                crate::client::metrics::Transfer::new(
                    1,
                    Duration::from_secs(if cancel { 2 } else { 3 })
                )
                .rate()
            );
        }
    }

    #[tokio::test]
    async fn run_records_each_outcome_once() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (client, server) =
            tokio::join!(sia_mux::dial_anonymous(a), sia_mux::accept_anonymous(b));
        let client = client.unwrap();
        let _server = server.unwrap();
        let metrics = Arc::new(Metrics::default());
        let host = PublicKey::new([1; 32]);
        for (result, expected_rate) in [
            (Err(TransportError::Transport("failed".into())), 100),
            (Ok(()), 80),
            (Err(TransportError::NoToken(host)), 80),
        ] {
            let stream = RpcStream {
                stream: client.dial_stream().unwrap(),
                metrics: metrics.clone(),
                host,
            };
            let success = result.is_ok();
            assert_eq!(stream.run(async |_| result).await.is_ok(), success);
            assert_eq!(metrics.failure_rate(host), expected_rate);
        }
    }

    #[tokio::test]
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

    /// Accepts mux connections for `seed`'s key, counting TCP accepts and
    /// finishing each handshake only after `delay`.
    async fn slow_host(seed: [u8; 32], delay: Duration) -> (HostEndpoint, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = accepts.clone();
        tokio::spawn(async move {
            let key = SigningKey::from_bytes(&seed);
            let mut conns = Vec::new();
            while let Ok((tcp, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::Relaxed);
                sleep(delay).await;
                if let Ok(mux) = sia_mux::accept(tcp, &key).await {
                    conns.push(mux);
                }
            }
        });
        let host = HostEndpoint {
            public_key: PrivateKey::from_seed(&seed).public_key(),
            addresses: vec![NetAddress {
                protocol: Protocol::SiaMux,
                address,
            }],
        };
        (host, accepts)
    }

    /// A dial outlives the caller that started it while another caller
    /// waits on it, and stops once nobody does.
    #[sia_core_derive::cross_target_test]
    async fn test_dial_runs_until_done_or_unwanted() {
        let (host, accepts) = slow_host([7u8; 32], Duration::from_millis(300)).await;
        let client = Client::new();
        let spawn_stream = || {
            let client = client.clone();
            let host = HostEndpoint {
                public_key: host.public_key,
                addresses: host.addresses.clone(),
            };
            AbortOnDropHandle::new(tokio::spawn(async move { client.host_stream(&host).await }))
        };

        // the starter is cancelled; the waiter still gets a stream on the
        // same connection
        let starter = spawn_stream();
        let waiter = spawn_stream();
        sleep(Duration::from_millis(50)).await;
        drop(starter);
        waiter
            .await
            .unwrap()
            .expect("the dial must survive its starter being cancelled");
        assert_eq!(accepts.load(Ordering::Relaxed), 1);
        client
            .host_stream(&host)
            .await
            .expect("the open connection is reused");
        assert_eq!(accepts.load(Ordering::Relaxed), 1);

        // with every waiter gone the dial is abandoned: the connection it was
        // making is never stored, so the next caller dials again
        let client = Client::new();
        let abandoned = {
            let client = client.clone();
            let host = HostEndpoint {
                public_key: host.public_key,
                addresses: host.addresses.clone(),
            };
            AbortOnDropHandle::new(tokio::spawn(async move { client.host_stream(&host).await }))
        };
        sleep(Duration::from_millis(50)).await;
        drop(abandoned);
        sleep(Duration::from_millis(400)).await;
        assert_eq!(accepts.load(Ordering::Relaxed), 2);
        client
            .host_stream(&host)
            .await
            .expect("a dial after the abandoned one must succeed");
        assert_eq!(
            accepts.load(Ordering::Relaxed),
            3,
            "an abandoned dial must not complete and populate the connection map"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sia_core::types::v2::NetAddress;
    use tokio::net::TcpListener;

    /// An announced IPv6 address is bracketed, and the brackets are not part
    /// of the address. Splitting on the last colon left them attached to the
    /// host, so every IPv6 host failed to resolve and no shard could reach it.
    ///
    /// The listener speaks no mux, so the connection is expected to fail. What
    /// matters is where: NoEndpoint means the address resolved and the socket
    /// connected, while a resolution failure surfaces as Io.
    #[tokio::test]
    async fn test_ipv6_address_resolves() {
        let listener = match TcpListener::bind("[::1]:0").await {
            Ok(l) => l,
            // no IPv6 loopback on this machine, nothing to assert
            Err(_) => return,
        };
        let port = listener.local_addr().unwrap().port();
        // Accept and drop, so the mux handshake fails on EOF. new_conn has no
        // timeout of its own, so a listener that never answers hangs forever.
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let host = HostEndpoint {
            public_key: PublicKey::new([1; 32]),
            addresses: vec![NetAddress {
                protocol: Protocol::SiaMux,
                address: format!("[::1]:{port}"),
            }],
        };

        match Client::new_conn(&host).await {
            Err(ConnectError::NoEndpoint) => {}
            Err(ConnectError::Io(e)) => panic!("address did not resolve: {e}"),
            Err(e) => panic!("expected NoEndpoint, got {e}"),
            Ok(_) => panic!("expected the mux handshake to fail"),
        }
    }
}
