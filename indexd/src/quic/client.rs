use bytes::Bytes;
use log::debug;
use priority_queue::PriorityQueue;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::ClientConfig;
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::{self, Error};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::lookup_host;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

use quinn::{Connection, Endpoint, RecvStream, SendStream};
use sia::encoding;
use sia::encoding_async::AsyncDecoder;
use sia::rhp::{
    self, AccountToken, Host, HostPrices, RPCReadSector, RPCSettings, RPCWriteSector, Transport,
};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use sia::types::v2::{NetAddress, Protocol};
use std::sync::Mutex;
use time::OffsetDateTime;

struct Stream {
    send: SendStream,
    recv: RecvStream,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to connect")]
    FailedToConnect,

    #[error("connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid port: {0}")]
    InvalidPort(#[from] ParseIntError),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("unknown host: {0}")]
    UnknownHost(PublicKey),

    #[error("encoding error: {0}")]
    Encoding(#[from] encoding::Error),

    #[error("rhp error: {0}")]
    RHP(#[from] rhp::Error),

    #[error("read error: {0}")]
    Read(#[from] quinn::ReadExactError),

    #[error("write error: {0}")]
    Write(#[from] quinn::WriteError),

    #[error("invalid prices")]
    InvalidPrices,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("timeout error: {0}")]
    Timeout(#[from] Elapsed),

    #[error("no endpoint")]
    NoEndpoint,
}

impl AsyncDecoder for Stream {
    type Error = Error;
    async fn decode_buf(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.recv.read_exact(buf).await?;
        Ok(())
    }
}

impl Transport for Stream {
    type Error = Error;

    async fn write_request<R: rhp::RPCRequest>(&mut self, req: &R) -> Result<(), Self::Error> {
        let mut w = BufWriter::new(&mut self.send);
        req.encode_request(&mut w).await?;
        w.flush().await?;
        Ok(())
    }

    async fn read_response<R: rhp::RPCResponse>(&mut self) -> Result<R, Self::Error> {
        R::decode_response(self).await
    }

    async fn write_response<RR: rhp::RPCResponse>(&mut self, resp: &RR) -> Result<(), Self::Error> {
        let mut w = BufWriter::new(&mut self.send);
        resp.encode_response(&mut w).await?;
        w.flush().await?;
        Ok(())
    }
}

/// A Client manages QUIC connections to Sia hosts.
/// Connections will be cached for reuse whenever possible.
#[derive(Debug, Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    pub fn new(client_config: ClientConfig) -> Result<Self, Error> {
        let inner = ClientInner::new(client_config)?;
        Ok(Client {
            inner: Arc::new(inner),
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
        let mut hosts_map = self.inner.hosts.lock().unwrap();
        let mut priority_queue = self.inner.preferred_hosts.lock().unwrap();
        hosts_map.clear();
        for host in hosts {
            hosts_map.insert(host.public_key, host.addresses);
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

#[derive(Debug)]
struct ClientInner {
    /*
        note: quinn's documentation (https://docs.rs/quinn/latest/quinn/struct.Endpoint.html#method.client) suggests
        non-ideal fallback behavior when dual-stack is not supported. This effectively treats every platform as
        single-stack instead since IPv4 is the preferred fallback.
    */
    endpoint_v4: Option<Endpoint>,
    endpoint_v6: Option<Endpoint>,

    hosts: Mutex<HashMap<PublicKey, Vec<NetAddress>>>,
    preferred_hosts: Mutex<PriorityQueue<PublicKey, i64>>,
    open_conns: Mutex<HashMap<PublicKey, Connection>>,
    cached_prices: Mutex<HashMap<PublicKey, HostPrices>>,
}

impl ClientInner {
    fn new(mut client_config: ClientConfig) -> Result<Self, Error> {
        client_config.enable_early_data = true;
        client_config.alpn_protocols = vec![b"sia/rhp4".to_vec()];

        let client_config = QuicClientConfig::try_from(client_config).unwrap();
        let client_config = quinn::ClientConfig::new(Arc::new(client_config));

        let endpoint_v4 = match quinn::Endpoint::client((Ipv4Addr::UNSPECIFIED, 0).into()) {
            Ok(mut endpoint) => {
                endpoint.set_default_client_config(client_config.clone());
                Some(endpoint)
            }
            Err(_) => None,
        };
        let endpoint_v6 = match quinn::Endpoint::client((Ipv6Addr::UNSPECIFIED, 0).into()) {
            Ok(mut endpoint) => {
                endpoint.set_default_client_config(client_config);
                Some(endpoint)
            }
            Err(_) => None,
        };

        if endpoint_v4.is_none() && endpoint_v6.is_none() {
            return Err(Error::NoEndpoint);
        }

        Ok(Self {
            endpoint_v4,
            endpoint_v6,
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

    fn existing_conn(&self, host: PublicKey) -> Option<Connection> {
        let mut open_conns = self.open_conns.lock().unwrap();
        if let Some(conn) = open_conns.get(&host).cloned() {
            if conn.close_reason().is_none() {
                return Some(conn);
            }
            open_conns.remove(&host);
        }
        None
    }

    async fn new_conn(&self, host: PublicKey) -> Result<Connection, Error> {
        let addresses = {
            let hosts = self.hosts.lock().unwrap();
            hosts.get(&host).cloned().ok_or(Error::UnknownHost(host))?
        };
        for addr in addresses {
            if addr.protocol != Protocol::QUIC {
                continue;
            }
            let (addr, port_str) = addr
                .address
                .rsplit_once(':')
                .ok_or(Error::InvalidAddress(addr.address.clone()))?;
            let port: u16 = port_str.parse()?;
            let resolved_addrs = lookup_host((addr, port)).await?;
            for socket in resolved_addrs {
                if socket.is_ipv6()
                    && let Some(endpoint) = &self.endpoint_v6
                {
                    let conn = endpoint.connect(socket, addr).unwrap().await.ok();
                    if let Some(conn) = conn {
                        return Ok(conn);
                    }
                } else if socket.is_ipv4()
                    && let Some(endpoint) = &self.endpoint_v4
                {
                    let conn = endpoint.connect(socket, addr).unwrap().await.ok();
                    if let Some(conn) = conn {
                        return Ok(conn);
                    }
                }
            }
        }
        Err(Error::FailedToConnect)
    }

    async fn host_stream(&self, host: PublicKey) -> Result<Stream, Error> {
        let conn = if let Some(conn) = self.existing_conn(host) {
            debug!("reusing existing connection to {host}");
            conn
        } else {
            let new_conn = timeout(Duration::from_secs(30), self.new_conn(host)).await??;
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
        let start = Instant::now();
        let resp = RPCSettings::send_request(stream).await?.complete().await?;
        debug!(
            "fetched prices for {host_key} in {}ms",
            start.elapsed().as_millis()
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
        let start = Instant::now();
        let resp = RPCWriteSector::send_request(stream, prices, token, sector)
            .await?
            .complete()
            .await?;
        debug!(
            "wrote sector to {host_key} in {}ms",
            start.elapsed().as_millis()
        );
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
        let start = Instant::now();
        let resp = RPCReadSector::send_request(stream, prices, token, root, offset, length)
            .await?
            .complete()
            .await?;
        debug!(
            "read {length} bytes from {host_key} in {}ms",
            start.elapsed().as_millis()
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

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;
    use rustls_platform_verifier::ConfigVerifierExt;
    use sia::public_key;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_dialer() {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .unwrap();
        }

        let host_key =
            public_key!("ed25519:36c8b07e61548a57e16dfabdfcc07dc157974a75010ab1684643d933e83fa7b1");

        let client_config =
            rustls::ClientConfig::with_platform_verifier().expect("Failed to create client config");

        let mut dialer = Client::new(client_config).expect("Failed to create dialer");
        dialer.update_hosts(vec![Host {
            public_key: host_key,
            addresses: vec![NetAddress {
                protocol: Protocol::QUIC,
                address: "6r4b0vj1ai55fobdvauvpg3to5bpeijl045b2q268fcj7q1vkuog.sia.host:9984"
                    .into(),
            }],
        }]);

        let prices = dialer
            .host_prices(host_key, false)
            .await
            .expect("Failed to get host prices");
        // check that they are cached
        let prices2 = dialer
            .host_prices(host_key, false)
            .await
            .expect("Failed to get host prices");
        assert_eq!(prices, prices2);
        sleep(Duration::from_secs(2)).await; // ensure the signature changes
        let prices3 = dialer
            .host_prices(host_key, true)
            .await
            .expect("Failed to get host prices");
        assert_ne!(prices2, prices3);
    }
}
