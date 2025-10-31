use bytes::Bytes;
use chrono::Utc;
use core::fmt::Debug;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use log::debug;
use quinn::crypto::rustls::QuicClientConfig;
use std::collections::HashMap;
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
use sia::types::v2::Protocol;
use std::sync::Mutex;

use crate::hosts::{HostQueue, Hosts};

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
        let inner = ClientInner::new(Hosts::new(), client_config)?;
        Ok(Client {
            inner: Arc::new(inner),
        })
    }

    /// Sorts a list of hosts according to their priority in the client's
    /// preferred hosts queue. The function `f` is used to extract the
    /// public key from each item.
    pub fn prioritize_hosts<H, F>(&self, hosts: &mut [H], f: F)
    where
        F: Fn(&H) -> &PublicKey,
    {
        self.inner.hosts.prioritize(hosts, f);
    }

    /// Updates the list of known hosts.
    ///
    /// Existing hosts not in the new list are removed, but
    /// their metrics are retained in case they reappear later.
    pub fn update_hosts(&self, hosts: Vec<Host>) {
        self.inner.hosts.update(hosts);
    }

    /// Returns a new host queue for selecting hosts
    /// according to their priority.
    pub fn host_queue(&self) -> HostQueue {
        self.inner.hosts.queue()
    }

    /// Returns the number of available hosts.
    pub fn available_hosts(&self) -> usize {
        self.inner.hosts.available()
    }

    /// Fetches the prices from a host optionally refreshing
    /// the cached prices.
    pub async fn host_prices(
        &self,
        host_key: PublicKey,
        refresh: bool,
    ) -> Result<HostPrices, Error> {
        self.inner
            .host_prices(host_key, refresh)
            .await
            .inspect_err(|_| {
                self.inner.hosts.add_failure(&host_key);
            })
    }

    /// Writes a sector to a host and returns the root hash.
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
                    .hosts
                    .add_write_sample(&host_key, start.elapsed());
            })
            .inspect_err(|_| {
                self.inner.hosts.add_failure(&host_key);
            })
    }

    /// Reads a segment of a sector from a host.
    ///
    /// # Arguments
    /// * `host_key` - The public key of the host to read from.
    /// * `account_key` - The private key of the account to pay with.
    /// * `root` - The root hash of the sector to read from.
    /// * `offset` - The offset within the sector to start reading from.
    /// * `length` - The length of the segment to read.
    ///
    /// # Returns
    /// A `Bytes` object containing the requested data segment. The
    /// returned data is validated against the sector's Merkle root.
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
                let elapsed = start.elapsed();
                debug!("read sector from {host_key} in {}ms", elapsed.as_millis());
                self.inner.hosts.add_read_sample(&host_key, elapsed);
            })
            .inspect_err(|_| {
                self.inner.hosts.add_failure(&host_key);
            })
    }
}

#[derive(Debug)]
struct ClientInner {
    hosts: Hosts,

    /*
        note: quinn's documentation (https://docs.rs/quinn/latest/quinn/struct.Endpoint.html#method.client) suggests
        non-ideal fallback behavior when dual-stack is not supported. This effectively treats every platform as
        single-stack instead since IPv4 is the preferred fallback.
    */
    endpoint_v4: Mutex<Option<Arc<Endpoint>>>,
    endpoint_v6: Mutex<Option<Arc<Endpoint>>>,
    consecutive_failures: AtomicU16,

    client_config: ClientConfig,

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

    fn new(hosts: Hosts, mut client_config: rustls::ClientConfig) -> Result<Self, Error> {
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
            hosts,
            endpoint_v4: Mutex::new(None),
            endpoint_v6: Mutex::new(None),
            client_config,
            consecutive_failures: AtomicU16::new(0),

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
        let addresses = self
            .hosts
            .addresses(&host)
            .ok_or(ConnectError::UnknownHost(host))?;
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

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;
    use rustls_platform_verifier::ConfigVerifierExt;
    use sia::public_key;
    use sia::rhp::Host;
    use sia::types::v2::NetAddress;
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
