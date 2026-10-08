use crate::time::{Elapsed, Instant, timeout};

use bytes::Bytes;
use core::fmt::Debug;
use ed25519_dalek::{SignatureError, VerifyingKey};
use log::debug;
use std::collections::HashMap;
use std::num::ParseIntError;
use std::ops::Range;
use std::sync::{Arc, Mutex, Weak};
use thiserror::{self, Error};
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::watch;

use crate::rhp4::HostEndpoint;
use crate::task::AbortOnDropHandle;
use crate::time::Duration;

use super::{Error as TransportError, Transport};
use sia_core::rhp4::protocol::{RPCReadSector, RPCSettings, RPCWriteSector};
use sia_core::rhp4::{AccountToken, HostPrices};
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

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("timeout error: {0}")]
    Elapsed(#[from] Elapsed),

    #[error("invalid port: {0}")]
    InvalidPort(#[from] ParseIntError),

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
            let (host_addr, port_str) = addr
                .address
                .rsplit_once(':')
                .ok_or(ConnectError::InvalidAddress(addr.address.clone()))?;
            let port: u16 = port_str.parse()?;
            let resolved_addrs = lookup_host((host_addr, port)).await?;

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
                        debug!("TCP connect failed to {host_addr}:{port} ({socket}): {e}");
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

impl Transport for Client {
    async fn host_prices(
        &self,
        host: &HostEndpoint,
        idle_timeout: Duration,
    ) -> Result<(HostPrices, Duration), TransportError> {
        let mut stream = self.host_stream(host).await?;
        stream.set_idle_timeout(Some(idle_timeout));
        let start = Instant::now();
        let resp = RPCSettings::send_request(&mut stream)
            .await?
            .complete(&mut stream)
            .await?;
        Ok((resp.settings.prices, start.elapsed()))
    }

    async fn write_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        data: Bytes,
        idle_timeout: Duration,
    ) -> Result<(Hash256, Duration), TransportError> {
        let token = AccountToken::new(account_key, host.public_key);
        let mut stream = self.host_stream(host).await?;
        stream.set_idle_timeout(Some(idle_timeout));
        let start = Instant::now();
        let resp = RPCWriteSector::send_request(&mut stream, prices, token, data)
            .await?
            .complete(&mut stream)
            .await?;
        Ok((resp.root, start.elapsed()))
    }

    async fn read_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        token: AccountToken,
        root: Hash256,
        range: Range<usize>,
        idle_timeout: Duration,
    ) -> Result<(Bytes, Duration), TransportError> {
        let mut stream = self.host_stream(host).await?;
        stream.set_idle_timeout(Some(idle_timeout));
        let start = Instant::now();
        let resp =
            RPCReadSector::send_request(&mut stream, prices, token, root, range.start, range.len())
                .await?
                .complete(&mut stream)
                .await?;
        Ok((resp.data, start.elapsed()))
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
