use bytes::Bytes;
use chrono::Utc;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use log::debug;
use priority_queue::PriorityQueue;
use quinn::crypto::rustls::QuicClientConfig;
use std::collections::{HashMap, VecDeque};
use std::num::ParseIntError;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use thiserror::{self, Error};
use tokio::net::lookup_host;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, VarInt};
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
pub enum ConnectError {
    #[error("connect error: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("timeout error: {0}")]
    Elapsed(#[from] Elapsed),

    #[error("unknown host: {0}")]
    UnknownHost(PublicKey),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid port: {0}")]
    InvalidPort(#[from] ParseIntError),

    #[error("no endpoint")]
    NoEndpoint,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to connect")]
    FailedToConnect,

    #[error("connect error: {0}")]
    Connect(#[from] ConnectError),

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
    pub fn new(client_config: rustls::ClientConfig) -> Result<Self, Error> {
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
        self.inner
            .host_prices(host_key, refresh)
            .await
            .inspect_err(|_| {
                self.inner
                    .preferred_hosts
                    .lock()
                    .unwrap()
                    .change_priority_by(&host_key, |metric| {
                        metric.add_failure();
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
                        metric.add_write_sample(elapsed);
                    });
            })
            .inspect_err(|_| {
                self.inner
                    .preferred_hosts
                    .lock()
                    .unwrap()
                    .change_priority_by(&host_key, |metric| {
                        metric.add_failure();
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
                        metric.add_read_sample(elapsed);
                    });
            })
            .inspect_err(|_| {
                self.inner
                    .preferred_hosts
                    .lock()
                    .unwrap()
                    .change_priority_by(&host_key, |metric| {
                        metric.add_failure();
                    });
            })
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
struct RPCAverage(u128, u64);

impl RPCAverage {
    fn add_sample(&mut self, sample: u128) {
        self.0 = self.0.saturating_add(sample);
        self.1 = self.1.saturating_add(1);
    }

    fn avg(&self) -> u128 {
        if self.1 == 0 {
            u128::MAX
        } else {
            self.0 / self.1 as u128
        }
    }
}

impl Ord for RPCAverage {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.avg().cmp(&self.avg()) // lower average latency is higher priority
    }
}

impl PartialOrd for RPCAverage {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
struct HostMetric {
    rpc_write_avg: RPCAverage,
    rpc_read_avg: RPCAverage,
    successful: i64, // negative values indicate failures
}

impl HostMetric {
    fn add_write_sample(&mut self, d: Duration) {
        self.rpc_write_avg.add_sample(d.as_millis());
        self.successful = self.successful.saturating_add(1);
    }

    fn add_read_sample(&mut self, d: Duration) {
        self.rpc_read_avg.add_sample(d.as_millis());
        self.successful = self.successful.saturating_add(1);
    }

    fn add_failure(&mut self) {
        self.successful = self.successful.saturating_sub(1);
    }
}

impl Ord for HostMetric {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let avg_self = (self
            .rpc_write_avg
            .avg()
            .saturating_add(self.rpc_read_avg.avg()))
            / 2;
        let avg_other = (other
            .rpc_write_avg
            .avg()
            .saturating_add(other.rpc_read_avg.avg()))
            / 2;
        match avg_other.cmp(&avg_self) {
            std::cmp::Ordering::Equal => self.successful.cmp(&other.successful), // more successful RPCs is higher priority
            ord => ord, // lower average speed is higher priority
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
    endpoint_v4: Mutex<Option<Arc<Endpoint>>>,
    endpoint_v6: Mutex<Option<Arc<Endpoint>>>,
    consecutive_failures: AtomicU16,

    client_config: ClientConfig,

    hosts: Mutex<HashMap<PublicKey, Vec<NetAddress>>>,
    preferred_hosts: Mutex<PriorityQueue<PublicKey, HostMetric>>,
    open_conns: Mutex<HashMap<PublicKey, Connection>>,
    cached_prices: Mutex<HashMap<PublicKey, HostPrices>>,
    cached_tokens: Mutex<HashMap<PublicKey, AccountToken>>,
}

impl ClientInner {
    const MAX_CONSECUTIVE_FAILURES: u16 = 5;

    fn init_quic_endpoints(&self) -> Result<(), ConnectError> {
        let endpoint_v4 = match quinn::Endpoint::client((Ipv4Addr::UNSPECIFIED, 0).into()) {
            Ok(mut endpoint) => {
                endpoint.set_default_client_config(self.client_config.clone());
                Some(Arc::new(endpoint))
            }
            Err(e) => {
                debug!("error opening IPv4 endpoint {:?}", e);
                None
            }
        };
        let endpoint_v6 = match quinn::Endpoint::client((Ipv6Addr::UNSPECIFIED, 0).into()) {
            Ok(mut endpoint) => {
                endpoint.set_default_client_config(self.client_config.clone());
                Some(Arc::new(endpoint))
            }
            Err(e) => {
                debug!("error opening IPv6 endpoint {:?}", e);
                None
            }
        };

        if endpoint_v4.is_none() && endpoint_v6.is_none() {
            return Err(ConnectError::NoEndpoint);
        }
        debug!(
            "initialized QUIC endpoints: v4={:?}, v6={:?}",
            endpoint_v4.clone().map(|e| e.local_addr()),
            endpoint_v6.clone().map(|e| e.local_addr())
        );

        // reset the endpoints, clear open connections, and reset failure count
        let mut open_conns = self.open_conns.lock().unwrap();
        open_conns.clear();

        let mut endpoint_v4_lock = self.endpoint_v4.lock().unwrap();
        *endpoint_v4_lock = endpoint_v4;
        let mut endpoint_v6_lock = self.endpoint_v6.lock().unwrap();
        *endpoint_v6_lock = endpoint_v6;

        self.consecutive_failures.store(0, Ordering::Relaxed);
        Ok(())
    }

    fn new(mut client_config: rustls::ClientConfig) -> Result<Self, Error> {
        const MAX_STREAM_BANDWIDTH: u64 = 1024 * 1024 * 1024; // 1 GiB/s
        const EXPECTED_RTT: u64 = 100; // ms
        client_config.enable_early_data = true;
        client_config.alpn_protocols = vec![b"sia/rhp4".to_vec()];

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(VarInt::from_u32(0));
        transport_config.max_concurrent_uni_streams(VarInt::from_u32(0));
        transport_config.max_idle_timeout(Some(Duration::from_secs(15).try_into().unwrap()));
        transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
        transport_config
            .stream_receive_window(VarInt::from_u64(MAX_STREAM_BANDWIDTH * EXPECTED_RTT).unwrap());

        let client_config = QuicClientConfig::try_from(client_config).unwrap();
        let mut client_config = quinn::ClientConfig::new(Arc::new(client_config));
        client_config.transport_config(Arc::new(transport_config));

        let client = Self {
            endpoint_v4: Mutex::new(None),
            endpoint_v6: Mutex::new(None),
            client_config,
            consecutive_failures: AtomicU16::new(0),

            hosts: Mutex::new(HashMap::new()),
            preferred_hosts: Mutex::new(PriorityQueue::new()),
            open_conns: Mutex::new(HashMap::new()),
            cached_prices: Mutex::new(HashMap::new()),
            cached_tokens: Mutex::new(HashMap::new()),
        };
        client.init_quic_endpoints()?;
        Ok(client)
    }

    async fn connect_v4(
        &self,
        socket_addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connection, ConnectError> {
        if self.consecutive_failures.load(Ordering::Relaxed) > Self::MAX_CONSECUTIVE_FAILURES {
            // The endpoint does not recover after resuming on some platforms (iOS). Effectively
            // re-binds the socket if more than MAX_CONSECUTIVE_FAILURES failures occur.
            self.init_quic_endpoints()?;
        }
        let endpoint = {
            let endpoint = self.endpoint_v4.lock().unwrap();
            match endpoint.as_ref() {
                None => return Err(ConnectError::NoEndpoint),
                Some(endpoint) => endpoint.clone(),
            }
        };

        let conn = endpoint
            .connect(socket_addr, server_name)
            .inspect_err(|e| {
                self.consecutive_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                debug!(
                    "failed to connect to {server_name} via {:?}: {e}",
                    endpoint.local_addr()
                );
            })?
            .await
            .inspect_err(|e| {
                self.consecutive_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                debug!(
                    "failed to establish connection to {server_name} via {:?}: {e}",
                    endpoint.local_addr()
                );
            })?;
        debug!(
            "established connection to {server_name} via {:?}",
            endpoint.local_addr()
        );
        self.consecutive_failures.store(0, Ordering::Relaxed);
        Ok(conn)
    }

    async fn connect_v6(
        &self,
        socket_addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connection, ConnectError> {
        if self.consecutive_failures.load(Ordering::Relaxed) > Self::MAX_CONSECUTIVE_FAILURES {
            // The endpoint does not recover after resuming on some platforms (iOS). Effectively
            // re-binds the socket if more than MAX_CONSECUTIVE_FAILURES failures occur.
            self.init_quic_endpoints()?;
        }
        let endpoint = {
            let endpoint = self.endpoint_v6.lock().unwrap();
            match endpoint.as_ref() {
                None => return Err(ConnectError::NoEndpoint),
                Some(endpoint) => endpoint.clone(),
            }
        };
        let conn = endpoint
            .connect(socket_addr, server_name)
            .inspect_err(|e| {
                self.consecutive_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                debug!(
                    "failed to connect to {server_name} via {:?}: {e}",
                    endpoint.local_addr()
                );
            })?
            .await
            .inspect_err(|e| {
                self.consecutive_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                debug!(
                    "failed to establish connection to {server_name} via {:?}: {e}",
                    endpoint.local_addr()
                );
            })?;
        debug!(
            "established connection to {server_name} via {:?}",
            endpoint.local_addr()
        );
        self.consecutive_failures.store(0, Ordering::Relaxed);
        Ok(conn)
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

    async fn connect_to_host(
        &self,
        socket_addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connection, ConnectError> {
        if socket_addr.is_ipv6() {
            return self.connect_v6(socket_addr, server_name).await;
        } else if socket_addr.is_ipv4() {
            return self.connect_v4(socket_addr, server_name).await;
        }
        Err(ConnectError::InvalidAddress(socket_addr.to_string()))
    }

    async fn new_conn(&self, host: PublicKey) -> Result<Connection, ConnectError> {
        let addresses = {
            let hosts = self.hosts.lock().unwrap();
            hosts
                .get(&host)
                .cloned()
                .ok_or(ConnectError::UnknownHost(host))?
        };
        for addr in addresses {
            if addr.protocol != Protocol::QUIC {
                continue;
            }
            let (addr, port_str) = addr
                .address
                .rsplit_once(':')
                .ok_or(ConnectError::InvalidAddress(addr.address.clone()))?;
            let port: u16 = port_str.parse()?;
            let resolved_addrs = lookup_host((addr, port)).await?;
            for socket in resolved_addrs {
                if let Ok(conn) = self.connect_to_host(socket, addr).await.inspect_err(|e| {
                    debug!("failed to connect to {addr}:{port} ({socket}) : {e}");
                }) {
                    return Ok(conn);
                }
            }
        }
        Err(ConnectError::NoEndpoint)
    }

    async fn host_stream(&self, host: PublicKey) -> Result<Stream, ConnectError> {
        let conn = if let Some(conn) = self.existing_conn(host) {
            debug!("reusing existing connection to {host}");
            conn
        } else {
            let now = Instant::now();
            let new_conn = timeout(Duration::from_secs(30), self.new_conn(host))
                .await
                .inspect_err(|e| {
                    debug!(
                        "new connection to {host} timed out in {:?}ms {e}",
                        now.elapsed().as_millis()
                    );
                })??;
            let open_conns = &mut self.open_conns.lock().unwrap();
            open_conns.insert(host, new_conn.clone());
            debug!("established new connection to {host}");
            new_conn
        };

        let (send, recv) = conn.open_bi().await.inspect_err(|_| {
            self.open_conns.lock().unwrap().remove(&host);
        })?;
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
        let prices = self.fetch_prices(host_key).await?;
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
