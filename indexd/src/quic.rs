use bytes::Bytes;
use chrono::Utc;
use core::fmt::Debug;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use log::debug;
use quinn::crypto::rustls::QuicClientConfig;
use std::collections::HashMap;
use std::num::ParseIntError;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use thiserror::{self, Error};
use tokio::net::lookup_host;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

use crate::rhp4::Error as RHP4Error;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, VarInt};
use sia::encoding_async::AsyncDecoder;
use sia::rhp::{
    self, AccountToken, HostPrices, RPCReadSector, RPCSettings, RPCWriteSector, Transport,
};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use sia::types::v2::Protocol;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use crate::{Hosts, RHP4Client};

struct Stream {
    send: Compat<SendStream>,
    recv: Compat<RecvStream>,
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

impl AsyncDecoder for Stream {
    type Error = RHP4Error;
    async fn decode_buf(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.recv
            .get_mut()
            .read_exact(buf)
            .await
            .map_err(|e| RHP4Error::Transport(e.to_string()))
    }
}

impl Transport for Stream {
    type Error = RHP4Error;

    async fn write_request<R: rhp::RPCRequest>(&mut self, req: &R) -> Result<(), Self::Error> {
        req.encode_request(&mut self.send).await?;
        Ok(())
    }

    async fn write_bytes(&mut self, data: Bytes) -> Result<(), Self::Error> {
        self.send
            .get_mut()
            .write_chunk(data)
            .await
            .map_err(|e| RHP4Error::Transport(e.to_string()))
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
#[derive(Debug)]
pub struct ClientInner {
    hosts: Hosts,
    /*
        note: quinn's documentation (https://docs.rs/quinn/latest/quinn/struct.Endpoint.html#method.client) suggests
        non-ideal fallback behavior when dual-stack is not supported. This effectively treats every platform as
        single-stack instead since IPv4 is the preferred fallback.
    */
    endpoint_v4: RwLock<Option<Arc<Endpoint>>>,
    endpoint_v6: RwLock<Option<Arc<Endpoint>>>,
    consecutive_failures: AtomicU16,

    client_config: ClientConfig,

    open_conns: RwLock<HashMap<PublicKey, Connection>>,
    cached_prices: RwLock<HashMap<PublicKey, HostPrices>>,
    cached_tokens: RwLock<HashMap<PublicKey, AccountToken>>,
}

impl ClientInner {
    const MAX_CONSECUTIVE_FAILURES: u16 = 5;

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
            let endpoint = self.endpoint_v4.read().unwrap();
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
            let endpoint = self.endpoint_v6.read().unwrap();
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

    fn get_cached_prices(&self, host_key: &PublicKey) -> Option<HostPrices> {
        let cached_prices = {
            let cache = self.cached_prices.read().unwrap();
            cache.get(host_key).cloned()
        };
        match cached_prices {
            Some(prices) if prices.valid_until > Utc::now() => Some(prices),
            _ => None,
        }
    }

    fn set_cached_prices(&self, host_key: &PublicKey, prices: HostPrices) {
        self.cached_prices
            .write()
            .unwrap()
            .insert(*host_key, prices);
    }

    fn existing_conn(&self, host: PublicKey) -> Option<Connection> {
        let open_conn = {
            let conn_cache = self.open_conns.read().unwrap();
            conn_cache.get(&host).cloned()
        };
        match open_conn {
            Some(conn) if conn.close_reason().is_none() => Some(conn),
            _ => None,
        }
    }

    fn account_token(&self, account_key: &PrivateKey, host_key: PublicKey) -> AccountToken {
        let cached_token = {
            let cache = self.cached_tokens.read().unwrap();
            cache.get(&host_key).cloned()
        };
        match cached_token {
            Some(token) if token.valid_until > Utc::now() => token.clone(),
            _ => {
                let token = AccountToken::new(account_key, host_key);
                self.cached_tokens
                    .write()
                    .unwrap()
                    .insert(host_key, token.clone());
                token
            }
        }
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
        let conn = match self.existing_conn(host) {
            Some(conn) => {
                debug!("reusing existing connection to {host}");
                conn
            }
            None => {
                let now = Instant::now();
                let new_conn = timeout(Duration::from_secs(30), self.new_conn(host))
                    .await
                    .inspect_err(|e| {
                        debug!(
                            "new connection to {host} timed out in {:?}ms {e}",
                            now.elapsed().as_millis()
                        );
                    })??;
                let mut open_conns = self.open_conns.write().unwrap();
                open_conns.insert(host, new_conn.clone());
                debug!("established new connection to {host}");
                new_conn
            }
        };

        let (send, recv) = conn.open_bi().await.inspect_err(|_| {
            self.open_conns.write().unwrap().remove(&host);
        })?;
        Ok(Stream {
            send: send.compat_write(),
            recv: recv.compat(),
        })
    }

    async fn host_prices(&self, host_key: PublicKey) -> Result<HostPrices, RHP4Error> {
        let stream = self
            .host_stream(host_key)
            .await
            .map_err(|e| RHP4Error::Transport(e.to_string()))?;
        let resp = RPCSettings::send_request(stream).await?.complete().await?;
        self.set_cached_prices(&host_key, resp.settings.prices.clone());
        Ok(resp.settings.prices)
    }

    async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        prices: HostPrices,
        sector: Bytes,
    ) -> Result<Hash256, RHP4Error> {
        let stream = self
            .host_stream(host_key)
            .await
            .map_err(|e| RHP4Error::Transport(e.to_string()))?;
        let token = self.account_token(account_key, host_key);
        let resp = RPCWriteSector::send_request(stream, prices, token, sector)
            .await?
            .complete()
            .await?;
        Ok(resp.root)
    }

    async fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        prices: HostPrices,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, RHP4Error> {
        let stream = self
            .host_stream(host_key)
            .await
            .map_err(|e| RHP4Error::Transport(e.to_string()))?;
        let token = self.account_token(account_key, host_key);
        let resp = RPCReadSector::send_request(stream, prices, token, root, offset, length)
            .await?
            .complete()
            .await?;
        Ok(resp.data)
    }

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
        let mut open_conns = self.open_conns.write().unwrap();
        open_conns.clear();

        let mut endpoint_v4_lock = self.endpoint_v4.write().unwrap();
        *endpoint_v4_lock = endpoint_v4;
        let mut endpoint_v6_lock = self.endpoint_v6.write().unwrap();
        *endpoint_v6_lock = endpoint_v6;

        self.consecutive_failures.store(0, Ordering::Relaxed);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    pub fn new(
        mut client_config: rustls::ClientConfig,
        hosts: Hosts,
    ) -> Result<Self, ConnectError> {
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
            inner: Arc::new(ClientInner {
                hosts,
                endpoint_v4: RwLock::new(None),
                endpoint_v6: RwLock::new(None),
                consecutive_failures: AtomicU16::new(0),
                client_config,
                open_conns: RwLock::new(HashMap::new()),
                cached_prices: RwLock::new(HashMap::new()),
                cached_tokens: RwLock::new(HashMap::new()),
            }),
        };
        client.inner.init_quic_endpoints()?;
        Ok(client)
    }
}

impl RHP4Client for Client {
    async fn host_prices(
        &self,
        host_key: PublicKey,
        refresh: bool,
    ) -> Result<HostPrices, RHP4Error> {
        if !refresh && let Some(prices) = self.inner.get_cached_prices(&host_key) {
            return Ok(prices);
        }
        self.inner
            .host_prices(host_key)
            .await
            .inspect_err(|_| self.inner.hosts.add_failure(&host_key))
    }

    async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> Result<Hash256, RHP4Error> {
        let prices = self.host_prices(host_key, false).await?;
        let start = Instant::now();
        let root = self
            .inner
            .write_sector(host_key, account_key, prices, sector)
            .await
            .inspect_err(|_| self.inner.hosts.add_failure(&host_key))?;
        self.inner
            .hosts
            .add_write_sample(&host_key, start.elapsed());
        Ok(root)
    }

    async fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, RHP4Error> {
        let prices = self.host_prices(host_key, false).await?;
        let start = Instant::now();
        let data = self
            .inner
            .read_sector(host_key, account_key, prices, root, offset, length)
            .await
            .inspect_err(|_| self.inner.hosts.add_failure(&host_key))?;
        self.inner.hosts.add_read_sample(&host_key, start.elapsed());
        Ok(data)
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
        let hosts = Hosts::new();
        hosts.update(vec![Host {
            public_key: host_key,
            addresses: vec![NetAddress {
                protocol: Protocol::QUIC,
                address: "6r4b0vj1ai55fobdvauvpg3to5bpeijl045b2q268fcj7q1vkuog.sia.host:9984"
                    .into(),
            }],
            country_code: "US".into(),
            latitude: 0.0,
            longitude: 0.0,
            good_for_upload: true,
        }]);
        let dialer = Client::new(client_config, hosts).expect("Failed to create dialer");

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
