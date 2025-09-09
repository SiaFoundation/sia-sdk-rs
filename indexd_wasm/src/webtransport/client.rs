use bytes::Bytes;
use chrono::DateTime;
use gloo_console::log;
use gloo_timers::future::TimeoutFuture;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::select;

use gloo_console::debug;
use priority_queue::PriorityQueue;
use sia::encoding;
use sia::encoding_async::AsyncDecoder;
use sia::rhp::{
    self, AccountToken, Host, HostPrices, RPCReadSector, RPCSettings, RPCWriteSector, Transport,
};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use sia::types::v2::{NetAddress, Protocol};
use thiserror::Error;
use time::OffsetDateTime;
use web_transport::{ClientBuilder, RecvStream, SendStream, Session};

const DEFAULT_BUFFER_SIZE: usize = 8 * 1024;

struct Stream {
    send: SendStream,
    recv: RecvStream,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to connect")]
    FailedToConnect,

    #[error("encoding error: {0}")]
    Encoding(#[from] encoding::Error),

    #[error("invalid prices")]
    InvalidPrices,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("url parse error: {0}")]
    Parse(#[from] url::ParseError),

    #[error("rhp error: {0}")]
    RHP(#[from] rhp::Error),

    #[error("stream was closed")]
    StreamClosed,

    #[error("timeout error")]
    Timeout,

    #[error("unknown host: {0}")]
    UnknownHost(PublicKey),

    #[error("web-transport error: {0}")]
    WebTransport(#[from] web_transport::Error),
}

impl AsyncDecoder for Stream {
    type Error = Error;
    async fn decode_buf(&mut self, mut buf: &mut [u8]) -> Result<(), Self::Error> {
        while !buf.is_empty() {
            if let Some(n) = self.recv.read_buf(&mut buf).await? {
                buf = &mut buf[n..];
            } else {
                return Err(Error::StreamClosed);
            }
        }
        Ok(())
    }
}

impl Transport for Stream {
    type Error = Error;

    async fn write_request<R: rhp::RPCRequest>(&mut self, req: &R) -> Result<(), Self::Error> {
        let mut buf = Vec::with_capacity(DEFAULT_BUFFER_SIZE);
        req.encode_request(&mut buf).await?;
        self.send.write(&buf[..]).await?;
        Ok(())
    }

    async fn read_response<R: rhp::RPCResponse>(&mut self) -> Result<R, Self::Error> {
        R::decode_response(self).await
    }

    async fn write_response<RR: rhp::RPCResponse>(&mut self, resp: &RR) -> Result<(), Self::Error> {
        let mut buf = Vec::with_capacity(DEFAULT_BUFFER_SIZE);
        resp.encode_response(&mut buf).await?;
        self.send.write(&buf[..]).await?;
        Ok(())
    }
}

/// A Client manages QUIC connections to Sia hosts.
/// Connections will be cached for reuse whenever possible.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            inner: Arc::new(ClientInner::new()?),
        })
    }

    pub fn hosts(&self) -> Vec<PublicKey> {
        let hosts = self.inner.hosts.lock().unwrap();
        let preferred_hosts = self.inner.preferred_hosts.lock().unwrap();
        preferred_hosts
            .iter()
            .map(|(host, _)| *host)
            .filter(|host| hosts.contains_key(host))
            .collect()
    }

    pub fn update_hosts(&mut self, hosts: Vec<Host>) {
        log!(format!("updating hosts from {} hosts", hosts.len()));
        let mut hosts_map = self.inner.hosts.lock().unwrap();
        let mut priority_queue = self.inner.preferred_hosts.lock().unwrap();
        hosts_map.clear();
        for host in hosts {
            let mut addresses = host.addresses;
            for addr in addresses.iter_mut() {
                if !addr.address.starts_with("https://") {
                    addr.address = format!("https://{}", addr.address);
                }
            }
            hosts_map.insert(host.public_key, addresses);
            if !priority_queue.contains(&host.public_key) {
                priority_queue.push(host.public_key, 1);
            }
        }
    }

    pub async fn host_prices(
        &self,
        host_key: PublicKey,
        refresh: bool,
    ) -> Result<HostPrices, Error> {
        self.inner
            .host_prices(host_key, refresh)
            .await
            .inspect(|_| {
                self.inner
                    .preferred_hosts
                    .lock()
                    .unwrap()
                    .change_priority_by(&host_key, |successful_rpcs| {
                        *successful_rpcs += 1;
                    });
            })
            .inspect_err(|_| {
                self.inner
                    .preferred_hosts
                    .lock()
                    .unwrap()
                    .change_priority_by(&host_key, |successful_rpcs| {
                        *successful_rpcs -= 1;
                    });
            })
    }

    pub async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> Result<Hash256, Error> {
        self.inner
            .write_sector(host_key, account_key, sector)
            .await
            .inspect(|_| {
                self.inner
                    .preferred_hosts
                    .lock()
                    .unwrap()
                    .change_priority_by(&host_key, |successful_rpcs| {
                        *successful_rpcs += 1;
                    });
            })
            .inspect_err(|_| {
                self.inner
                    .preferred_hosts
                    .lock()
                    .unwrap()
                    .change_priority_by(&host_key, |successful_rpcs| {
                        *successful_rpcs -= 1;
                    });
            })
    }

    pub async fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, Error> {
        self.inner
            .read_sector(host_key, account_key, root, offset, length)
            .await
            .inspect(|_| {
                self.inner
                    .preferred_hosts
                    .lock()
                    .unwrap()
                    .change_priority_by(&host_key, |successful_rpcs| {
                        *successful_rpcs += 1;
                    });
            })
            .inspect_err(|_| {
                self.inner
                    .preferred_hosts
                    .lock()
                    .unwrap()
                    .change_priority_by(&host_key, |successful_rpcs| {
                        *successful_rpcs -= 1;
                    });
            })
    }
}

struct ClientInner {
    client: web_transport::Client,
    hosts: Mutex<HashMap<PublicKey, Vec<NetAddress>>>,
    preferred_hosts: Mutex<PriorityQueue<PublicKey, i64>>,
    open_conns: Mutex<HashMap<PublicKey, Session>>,
    cached_prices: Mutex<HashMap<PublicKey, HostPrices>>,
}

impl ClientInner {
    fn new() -> Result<Self, Error> {
        let client = ClientBuilder::new().with_system_roots()?;
        Ok(Self {
            client,
            hosts: Mutex::new(HashMap::new()),
            preferred_hosts: Mutex::new(PriorityQueue::new()),
            open_conns: Mutex::new(HashMap::new()),
            cached_prices: Mutex::new(HashMap::new()),
        })
    }

    fn get_cached_prices(&self, host_key: &PublicKey) -> Option<HostPrices> {
        let mut cached_prices = self.cached_prices.lock().unwrap();
        match cached_prices.get(host_key) {
            Some(prices) => {
                if prices.valid_until < OffsetDateTime::now_utc() {
                    cached_prices.remove(host_key);
                    None
                } else {
                    Some(prices.clone())
                }
            }
            _ => None,
        }
    }

    fn set_cached_prices(&self, host_key: &PublicKey, prices: HostPrices) {
        self.cached_prices.lock().unwrap().insert(*host_key, prices);
    }

    fn existing_conn(&self, _host: PublicKey) -> Option<Session> {
        None // TODO: remove
    }

    async fn new_session(&self, host: PublicKey) -> Result<Session, Error> {
        let addresses = {
            let hosts = self.hosts.lock().unwrap();
            hosts.get(&host).cloned().ok_or(Error::UnknownHost(host))?
        };
        for addr in addresses {
            if addr.protocol != Protocol::QUIC {
                continue;
            }

            return Ok(self.client.connect(addr.address.parse()?).await?);
        }
        Err(Error::FailedToConnect)
    }

    async fn host_stream(&self, host: PublicKey) -> Result<Stream, Error> {
        let mut conn = if let Some(conn) = self.existing_conn(host) {
            debug!("reusing existing connection to {host}");
            conn
        } else {
            let new_conn = select! {
                conn = self.new_session(host) => conn,
                _ = TimeoutFuture::new(30000) =>  Err(Error::Timeout),

            }?;
            let open_conns = &mut self.open_conns.lock().unwrap();
            open_conns.insert(host, new_conn.clone());
            debug!("established new connection to {host}");
            new_conn
        };

        let (send, recv) = conn.open_bi().await?;
        Ok(Stream { send, recv })
    }

    pub async fn host_prices(
        &self,
        host_key: PublicKey,
        refresh: bool,
    ) -> Result<HostPrices, Error> {
        if !refresh && let Some(prices) = self.get_cached_prices(&host_key) {
            debug!("using cached prices for {host_key}");
            return Ok(prices);
        }
        let stream = self.host_stream(host_key).await?;
        let start = chrono::Utc::now();
        let resp = RPCSettings::send_request(stream).await?.complete().await?;
        debug!(
            "fetched prices for {host_key} in {}ms",
            (chrono::Utc::now() - start).num_milliseconds()
        );
        let prices = resp.settings.prices;
        if prices.valid_until < OffsetDateTime::now_utc() {
            return Err(Error::InvalidPrices);
        } else if !host_key.verify(prices.sig_hash().as_ref(), &prices.signature) {
            return Err(Error::InvalidSignature);
        }
        self.set_cached_prices(&host_key, prices.clone());
        Ok(prices)
    }

    pub async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> Result<Hash256, Error> {
        let prices = self.host_prices(host_key, false).await?;
        let token = AccountToken::new(account_key, host_key);
        let stream = self.host_stream(host_key).await?;
        let start = chrono::Utc::now();
        let resp = RPCWriteSector::send_request(stream, prices, token, sector)
            .await?
            .complete()
            .await?;
        debug!(format!(
            "wrote sector to {host_key} in {}ms",
            (chrono::Utc::now() - start).num_milliseconds()
        ));
        Ok(resp.root)
    }

    pub async fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, Error> {
        let prices = self.host_prices(host_key, false).await?;
        let token = AccountToken::new(account_key, host_key);
        let stream = self.host_stream(host_key).await?;
        let start = chrono::Utc::now();
        let resp = RPCReadSector::send_request(stream, prices, token, root, offset, length)
            .await?
            .complete()
            .await?;
        debug!(
            "read {length} bytes from {host_key} in {}ms",
            (chrono::Utc::now() - start).num_milliseconds()
        );
        Ok(resp.data)
    }
}

#[derive(Debug, Error)]
pub enum QueueError {
    #[error("no more hosts available")]
    NoMoreHosts,
    #[error("client closed")]
    Closed,

    #[error("internal mutex error")]
    MutexError,
}

/// A thread-safe queue of host public keys.
#[derive(Debug, Clone)]
pub struct HostQueue(Arc<Mutex<VecDeque<PublicKey>>>);

impl HostQueue {
    pub fn new(hosts: Vec<PublicKey>) -> Self {
        Self(Arc::new(Mutex::new(VecDeque::from(hosts))))
    }

    pub fn pop_front(&self) -> Result<PublicKey, QueueError> {
        self.0
            .lock()
            .map_err(|_| QueueError::MutexError)?
            .pop_front()
            .ok_or(QueueError::NoMoreHosts)
    }

    pub fn retry(&self, host: PublicKey) -> Result<(), QueueError> {
        self.0
            .lock()
            .map_err(|_| QueueError::MutexError)?
            .push_back(host);
        Ok(())
    }
}
