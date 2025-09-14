use bytes::Bytes;
use chrono::Utc;
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
use tokio::net::lookup_host;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use sia::encoding;
use sia::encoding_async::AsyncDecoder;
use sia::rhp::{
    self, AccountToken, Host, HostPrices, RPCReadSector, RPCSettings, RPCWriteSector, Transport,
};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use sia::types::v2::{NetAddress, Protocol};
use std::sync::Mutex;

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
        req.encode_request(&mut self.send).await?;
        Ok(())
    }

    async fn write_bytes(&mut self, data: Bytes) -> Result<(), Self::Error> {
        self.send.write_chunk(data).await?;
        Ok(())
    }

    async fn read_response<R: rhp::RPCResponse>(&mut self) -> Result<R, Self::Error> {
        R::decode_response(self).await
    }

    async fn write_response<RR: rhp::RPCResponse>(&mut self, resp: &RR) -> Result<(), Self::Error> {
        resp.encode_response(&mut self.send).await?;
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
        self.inner
            .preferred_hosts
            .lock()
            .unwrap()
            .clone()
            .into_sorted_iter()
            .map(|(host, _)| host)
            .filter(|host| hosts.contains_key(host))
            .collect()
    }

    pub fn update_hosts(&self, hosts: Vec<Host>) {
        let mut hosts_map = self.inner.hosts.lock().unwrap();
        let mut priority_queue = self.inner.preferred_hosts.lock().unwrap();
        hosts_map.clear();
        for host in hosts {
            hosts_map.insert(host.public_key, host.addresses);
            if !priority_queue.contains(&host.public_key) {
                priority_queue.push(host.public_key, HostMetric::default());
            }
        }
    }

    pub async fn host_prices(
        &self,
        host_key: PublicKey,
        refresh: bool,
    ) -> Result<HostPrices, Error> {
        let start = Instant::now();
        self.inner
            .host_prices(host_key, refresh)
            .await
            .inspect(|_| {
                self.inner
                    .preferred_hosts
                    .lock()
                    .unwrap()
                    .change_priority_by(&host_key, |metric| {
                        metric.add_sample(start.elapsed());
                    });
            })
    }

    pub async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> Result<Hash256, Error> {
        let start = Instant::now();
        self.inner
            .write_sector(host_key, account_key, sector)
            .await
            .inspect(|_| {
                self.inner
                    .preferred_hosts
                    .lock()
                    .unwrap()
                    .change_priority_by(&host_key, |metric| {
                        let elapsed = start.elapsed();
                        debug!("wrote sector to {host_key} in {}ms", elapsed.as_millis());
                        metric.add_sample(elapsed);
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
        let start = Instant::now();
        self.inner
            .read_sector(host_key, account_key, root, offset, length)
            .await
            .inspect(|_| {
                self.inner
                    .preferred_hosts
                    .lock()
                    .unwrap()
                    .change_priority_by(&host_key, |metric| {
                        let elapsed = start.elapsed();
                        debug!("read sector from {host_key} in {}ms", elapsed.as_millis());
                        metric.add_sample(elapsed);
                    });
            })
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
struct HostMetric {
    rpc_millis: u128,
    successful: u64,
}

impl HostMetric {
    fn add_sample(&mut self, d: Duration) {
        self.rpc_millis = self.rpc_millis.saturating_add(d.as_millis());
        self.successful = self.successful.saturating_add(1);
    }

    fn avg(&self) -> u128 {
        if self.successful == 0 {
            u128::MAX
        } else {
            self.rpc_millis / self.successful as u128
        }
    }
}

impl Ord for HostMetric {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match other.avg().cmp(&self.avg()) {
            std::cmp::Ordering::Equal => self.successful.cmp(&other.successful), // more successful RPCs is higher priority
            ord => ord, // lower average latency is higher priority
        }
    }
}

impl PartialOrd for HostMetric {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
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
    preferred_hosts: Mutex<PriorityQueue<PublicKey, HostMetric>>,
    open_conns: Mutex<HashMap<PublicKey, Connection>>,
    cached_prices: Mutex<HashMap<PublicKey, HostPrices>>,
    cached_tokens: Mutex<HashMap<PublicKey, AccountToken>>,
}

impl ClientInner {
    fn new(mut client_config: ClientConfig) -> Result<Self, Error> {
        const MAX_STREAM_BANDWIDTH: u64 = 1024 * 1024 * 1024; // 1 GiB/s
        const EXPECTED_RTT: u64 = 100; // ms
        client_config.enable_early_data = true;
        client_config.alpn_protocols = vec![b"sia/rhp4".to_vec()];

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(VarInt::from_u32(0));
        transport_config.max_concurrent_uni_streams(VarInt::from_u32(0));
        transport_config.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));
        transport_config.keep_alive_interval(Some(Duration::from_secs(10)));
        transport_config
            .stream_receive_window(VarInt::from_u64(MAX_STREAM_BANDWIDTH * EXPECTED_RTT).unwrap());

        let client_config = QuicClientConfig::try_from(client_config).unwrap();
        let mut client_config = quinn::ClientConfig::new(Arc::new(client_config));
        client_config.transport_config(Arc::new(transport_config));

        let endpoint_v4 = match quinn::Endpoint::client((Ipv4Addr::UNSPECIFIED, 0).into()) {
            Ok(mut endpoint) => {
                endpoint.set_default_client_config(client_config.clone());
                Some(endpoint)
            }
            Err(e) => {
                debug!("error opening IPv4 endpoint {:?}", e);
                None
            }
        };
        let endpoint_v6 = match quinn::Endpoint::client((Ipv6Addr::UNSPECIFIED, 0).into()) {
            Ok(mut endpoint) => {
                endpoint.set_default_client_config(client_config);
                Some(endpoint)
            }
            Err(e) => {
                debug!("error opening IPv6 endpoint {:?}", e);
                None
            }
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
            cached_tokens: Mutex::new(HashMap::new()),
        })
    }

    fn get_token(&self, host_key: &PublicKey, account_key: &PrivateKey) -> AccountToken {
        let mut cached_tokens = self.cached_tokens.lock().unwrap();
        if let Some(token) = cached_tokens.get(host_key)
            && token.valid_until > Utc::now()
        {
            return token.clone();
        }
        let token = AccountToken::new(account_key, *host_key);
        cached_tokens.insert(*host_key, token.clone());
        token
    }

    fn get_cached_prices(&self, host_key: &PublicKey) -> Option<HostPrices> {
        let mut cached_prices = self.cached_prices.lock().unwrap();
        match cached_prices.get(host_key) {
            Some(prices) => {
                if prices.valid_until < Utc::now() {
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
            conn
        } else {
            let new_conn = timeout(Duration::from_secs(30), self.new_conn(host)).await??;
            let open_conns = &mut self.open_conns.lock().unwrap();
            open_conns.insert(host, new_conn.clone());
            new_conn
        };

        let (send, recv) = conn.open_bi().await?;
        Ok(Stream { send, recv })
    }

    async fn fetch_prices(&self, host_key: PublicKey) -> Result<HostPrices, Error> {
        let stream = self.host_stream(host_key).await?;
        let resp = RPCSettings::send_request(stream).await?.complete().await?;
        let prices = resp.settings.prices;
        if prices.valid_until < Utc::now() {
            return Err(Error::InvalidPrices);
        } else if !host_key.verify(prices.sig_hash().as_ref(), &prices.signature) {
            return Err(Error::InvalidSignature);
        }
        Ok(prices)
    }

    pub async fn host_prices(
        &self,
        host_key: PublicKey,
        refresh: bool,
    ) -> Result<HostPrices, Error> {
        if !refresh && let Some(prices) = self.get_cached_prices(&host_key) {
            return Ok(prices);
        }
        let prices = timeout(Duration::from_millis(750), self.fetch_prices(host_key)).await??;
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
        let token = self.get_token(&host_key, account_key);
        let stream = self.host_stream(host_key).await?;
        let resp = RPCWriteSector::send_request(stream, prices, token, sector)
            .await?
            .complete()
            .await?;
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
        let token = self.get_token(&host_key, account_key);
        let stream = self.host_stream(host_key).await?;
        let resp = RPCReadSector::send_request(stream, prices, token, root, offset, length)
            .await?
            .complete()
            .await?;
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

#[derive(Debug)]
struct HostQueueInner {
    hosts: VecDeque<PublicKey>,
    attempts: HashMap<PublicKey, usize>,
}

/// A thread-safe queue of host public keys.
#[derive(Debug, Clone)]
pub struct HostQueue {
    inner: Arc<Mutex<HostQueueInner>>,
}

impl HostQueue {
    pub fn new(hosts: Vec<PublicKey>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HostQueueInner {
                hosts: VecDeque::from(hosts),
                attempts: HashMap::new(),
            })),
        }
    }

    pub fn pop_front(&self) -> Result<(PublicKey, usize), QueueError> {
        let mut inner = self.inner.lock().map_err(|_| QueueError::MutexError)?;
        let host_key = inner.hosts.pop_front().ok_or(QueueError::NoMoreHosts)?;

        let attempts = inner.attempts.get(&host_key).cloned().unwrap_or(0);
        Ok((host_key, attempts + 1))
    }

    pub fn retry(&self, host: PublicKey) -> Result<(), QueueError> {
        let mut inner = self.inner.lock().map_err(|_| QueueError::MutexError)?;
        inner.hosts.push_back(host);
        inner
            .attempts
            .entry(host)
            .and_modify(|e| *e += 1)
            .or_insert(1);
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

        let dialer = Client::new(client_config).expect("Failed to create dialer");
        dialer.update_hosts(vec![Host {
            public_key: host_key,
            addresses: vec![NetAddress {
                protocol: Protocol::QUIC,
                address: "6r4b0vj1ai55fobdvauvpg3to5bpeijl045b2q268fcj7q1vkuog.sia.host:9984"
                    .into(),
            }],
            country_code: "US".into(),
            latitude: 0.0,
            longitude: 0.0,
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
