use crate::time::{Elapsed, timeout};

use bytes::Bytes;
use core::fmt::Debug;
use ed25519_dalek::{SignatureError, VerifyingKey};
use log::debug;
use std::collections::HashMap;
use std::num::ParseIntError;
use std::sync::{Arc, RwLock};
use thiserror::{self, Error};
use tokio::net::{TcpStream, lookup_host};

use crate::rhp4::HostEndpoint;
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

#[derive(Clone)]
pub struct Client {
    open_conns: Arc<RwLock<HashMap<PublicKey, Arc<Mux>>>>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Self {
            open_conns: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn existing_conn(&self, host: &PublicKey) -> Option<Arc<Mux>> {
        let cache = self.open_conns.read().unwrap();
        cache.get(host).cloned()
    }

    async fn new_conn(&self, host: &HostEndpoint) -> Result<Mux, ConnectError> {
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

    async fn host_stream(&self, host: &HostEndpoint) -> Result<Stream, ConnectError> {
        let conn = match self.existing_conn(&host.public_key) {
            Some(conn) => {
                conn
            }
            None => {
                let new_conn = timeout(Duration::from_secs(5), self.new_conn(host))
                    .await
                    .inspect_err(|e| {
                        debug!("siamux connection to {} timed out: {e}", host.public_key);
                    })??;
                let new_conn = Arc::new(new_conn);
                self.open_conns
                    .write()
                    .unwrap()
                    .insert(host.public_key, new_conn.clone());
                new_conn
            }
        };

        let stream = conn.dial_stream().inspect_err(|_| {
            self.open_conns.write().unwrap().remove(&host.public_key);
        })?;
        Ok(stream)
    }
}

impl Transport for Client {
    async fn host_prices(&self, host: &HostEndpoint) -> Result<HostPrices, TransportError> {
        let mut stream = self
            .host_stream(host)
            .await
            .map_err(|e| TransportError::Transport(e.to_string()))?;
        let resp = RPCSettings::send_request(&mut stream)
            .await?
            .complete(&mut stream)
            .await?;
        Ok(resp.settings.prices)
    }

    async fn write_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        data: Bytes,
    ) -> Result<Hash256, TransportError> {
        let token = AccountToken::new(account_key, host.public_key);
        let mut stream = self
            .host_stream(host)
            .await
            .map_err(|e| TransportError::Transport(e.to_string()))?;
        let resp = RPCWriteSector::send_request(&mut stream, prices, token, data)
            .await?
            .complete(&mut stream)
            .await?;
        Ok(resp.root)
    }

    async fn read_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, TransportError> {
        let token = AccountToken::new(account_key, host.public_key);
        let mut stream = self
            .host_stream(host)
            .await
            .map_err(|e| TransportError::Transport(e.to_string()))?;
        let resp = RPCReadSector::send_request(&mut stream, prices, token, root, offset, length)
            .await?
            .complete(&mut stream)
            .await?;
        Ok(resp.data)
    }
}
