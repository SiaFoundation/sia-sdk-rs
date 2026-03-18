use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use core::fmt::Debug;
use ed25519_dalek::{SignatureError, VerifyingKey};
use log::debug;
use std::collections::HashMap;
use std::num::ParseIntError;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use thiserror::{self, Error};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, lookup_host};
use tokio::time::error::Elapsed;
use tokio::time::timeout;

use crate::rhp4::{Error as RHP4Error, RHP4Transport};
use crate::{Hosts, RHP4Client};
use sia::encoding_async::AsyncDecoder;
use sia::rhp::{
    self, AccountToken, HostPrices, RPCReadSector, RPCSettings, RPCWriteSector, Transport,
};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use sia::types::v2::Protocol;

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

    #[error("Host has no net address: {0}")]
    UnknownHost(PublicKey),

    #[error("invalid port: {0}")]
    InvalidPort(#[from] ParseIntError),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[from] SignatureError),

    #[error("no endpoint")]
    NoEndpoint,
}

struct MuxStream(sia_mux::Stream);

impl AsyncDecoder for MuxStream {
    type Error = RHP4Error;
    async fn decode_buf(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        use tokio::io::AsyncReadExt;
        self.0
            .read_exact(buf)
            .await
            .map(|_| ())
            .map_err(|e| RHP4Error::Transport(e.to_string()))
    }
}

impl Transport for MuxStream {
    type Error = RHP4Error;

    async fn write_request<R: rhp::RPCRequest>(&mut self, req: &R) -> Result<(), Self::Error> {
        req.encode_request(&mut self.0).await?;
        Ok(())
    }

    async fn write_bytes(&mut self, data: Bytes) -> Result<(), Self::Error> {
        self.0
            .write_all(&data)
            .await
            .map_err(|e| RHP4Error::Transport(e.to_string()))
    }

    async fn read_response<R: rhp::RPCResponse>(&mut self) -> Result<R, Self::Error> {
        R::decode_response(self).await
    }

    async fn write_response<RR: rhp::RPCResponse>(&mut self, resp: &RR) -> Result<(), Self::Error> {
        resp.encode_response(&mut self.0).await?;
        Ok(())
    }
}

struct ClientInner {
    hosts: Hosts,
    open_conns: RwLock<HashMap<PublicKey, Arc<sia_mux::Mux>>>,
    cached_prices: RwLock<HashMap<PublicKey, HostPrices>>,
    cached_tokens: RwLock<HashMap<PublicKey, AccountToken>>,
}

impl ClientInner {
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

    fn existing_conn(&self, host: &PublicKey) -> Option<Arc<sia_mux::Mux>> {
        let cache = self.open_conns.read().unwrap();
        cache.get(host).cloned()
    }

    async fn new_conn(&self, host: PublicKey) -> Result<sia_mux::Mux, ConnectError> {
        let addresses = self
            .hosts
            .addresses(&host)
            .ok_or(ConnectError::UnknownHost(host))?;
        for addr in addresses {
            if addr.protocol != Protocol::SiaMux {
                continue;
            }
            let (host_addr, port_str) = addr
                .address
                .rsplit_once(':')
                .ok_or(ConnectError::InvalidAddress(addr.address.clone()))?;
            let port: u16 = port_str.parse()?;
            let resolved_addrs = lookup_host((host_addr, port)).await?;

            let host_bytes: [u8; 32] = host.into();
            let verifying_key = VerifyingKey::from_bytes(&host_bytes)?;

            for socket in resolved_addrs {
                match TcpStream::connect(socket).await {
                    Ok(tcp) => match sia_mux::dial(tcp, &verifying_key).await {
                        Ok(mux_conn) => {
                            debug!("established siamux connection to {host} via {socket}");
                            return Ok(mux_conn);
                        }
                        Err(e) => {
                            debug!("mux handshake failed to {host} via {socket}: {e}");
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

    async fn host_stream(&self, host: PublicKey) -> Result<MuxStream, ConnectError> {
        // Try existing connection first
        if let Some(conn) = self.existing_conn(&host) {
            match conn.dial_stream() {
                Ok(stream) => {
                    debug!("reusing existing siamux connection to {host}");
                    return Ok(MuxStream(stream));
                }
                Err(_) => {
                    self.open_conns.write().unwrap().remove(&host);
                }
            }
        }

        // Establish new connection
        let new_conn = timeout(Duration::from_secs(30), self.new_conn(host))
            .await
            .inspect_err(|e| {
                debug!("siamux connection to {host} timed out: {e}");
            })??;
        let stream = new_conn.dial_stream()?;
        self.open_conns
            .write()
            .unwrap()
            .insert(host, Arc::new(new_conn));
        Ok(MuxStream(stream))
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
}

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("siamux::Client").finish()
    }
}

impl Client {
    pub fn new(hosts: Hosts) -> Self {
        Self {
            inner: Arc::new(ClientInner {
                hosts,
                open_conns: RwLock::new(HashMap::new()),
                cached_prices: RwLock::new(HashMap::new()),
                cached_tokens: RwLock::new(HashMap::new()),
            }),
        }
    }
}

#[async_trait]
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

impl RHP4Transport for Client {
    fn supported_protocols(&self) -> &[&str] {
        &["siamux"]
    }
}
