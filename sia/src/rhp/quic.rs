use quinn::crypto::rustls::QuicClientConfig;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::num::ParseIntError;
use std::sync::Arc;
use thiserror::{self, Error};

use crate::encoding;
use crate::encoding_async::{AsyncDecoder, AsyncEncoder};
use crate::objects::{Error as UploadError, HostDialer};
use crate::rhp::{
    self, AccountToken, Host, HostPrices, RPCReadSector, RPCSettings, RPCWriteSector, Transport,
};
use crate::signing::{PrivateKey, PublicKey};
use crate::types::Hash256;
use crate::types::v2::{NetAddress, Protocol};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
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

    #[error("upload error: {0}")]
    Upload(#[from] UploadError),

    #[error("invalid prices")]
    InvalidPrices,

    #[error("invalid signature")]
    InvalidSignature,

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

impl AsyncEncoder for Stream {
    type Error = Error;
    async fn encode_buf(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.send.write_all(buf).await?;
        Ok(())
    }
}

impl Transport for Stream {
    type Error = Error;

    async fn write_request<R: rhp::RPCRequest>(&mut self, req: &R) -> Result<(), Self::Error> {
        req.encode_request(self).await
    }

    async fn read_response<R: rhp::RPCResponse>(&mut self) -> Result<R, Self::Error> {
        R::decode_response(self).await
    }

    async fn write_response<R: rhp::RPCResponse>(&mut self, resp: &R) -> Result<(), Self::Error> {
        resp.encode_response(self).await
    }
}

/// A Dialer manages QUIC connections to Sia hosts.
/// Connections will be cached for reuse whenever possible.
#[derive(Debug, Clone)]
pub struct Dialer {
    inner: Arc<DialerInner>,
}

impl Dialer {
    pub fn new(client_config: ClientConfig) -> Result<Self, Error> {
        let inner = DialerInner::new(client_config)?;
        Ok(Dialer {
            inner: Arc::new(inner),
        })
    }

    fn get_cached_prices(&self, host_key: &PublicKey) -> Option<HostPrices> {
        let mut cached_prices = self.inner.cached_prices.lock().unwrap();
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
        self.inner
            .cached_prices
            .lock()
            .unwrap()
            .insert(*host_key, prices);
    }

    fn existing_conn(&self, host: PublicKey) -> Option<Connection> {
        let mut open_conns = self.inner.open_conns.lock().unwrap();
        if let Some(conn) = open_conns.get(&host).cloned() {
            if conn.close_reason().is_none() {
                return Some(conn);
            }
            open_conns.remove(&host);
        }
        None
    }

    async fn host_stream(&self, host: PublicKey) -> Result<Stream, Error> {
        let conn = if let Some(conn) = self.existing_conn(host) {
            conn
        } else {
            let addresses = {
                let hosts = self.inner.hosts.lock().unwrap();
                hosts.get(&host).cloned().ok_or(Error::UnknownHost(host))?
            };
            let mut new_conn = None;
            for addr in addresses {
                if addr.protocol != Protocol::QUIC {
                    continue;
                }
                let (addr, port_str) = addr
                    .address
                    .rsplit_once(':')
                    .ok_or(Error::InvalidAddress(addr.address.clone()))?;
                let port: u16 = port_str.parse()?;
                let resolved_addrs = (addr, port).to_socket_addrs()?;
                for socket in resolved_addrs {
                    if socket.is_ipv6()
                        && let Some(endpoint) = &self.inner.endpoint_v6
                    {
                        let conn = endpoint.connect(socket, addr).unwrap().await.ok();
                        if let Some(conn) = conn {
                            new_conn = Some(conn);
                            break;
                        }
                    } else if socket.is_ipv4()
                        && let Some(endpoint) = &self.inner.endpoint_v4
                    {
                        let conn = endpoint.connect(socket, addr).unwrap().await.ok();
                        if let Some(conn) = conn {
                            new_conn = Some(conn);
                            break;
                        }
                    }
                }

                if new_conn.is_some() {
                    break;
                }
            }

            let conn = new_conn.ok_or(Error::FailedToConnect)?;
            let open_conns = &mut self.inner.open_conns.lock().unwrap();
            open_conns.insert(host, conn.clone());
            conn
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
            return Ok(prices);
        }

        let stream = self.host_stream(host_key).await?;
        let resp = RPCSettings::send_request(stream).await?.complete().await?;
        let prices = resp.settings.prices;
        if prices.valid_until < OffsetDateTime::now_utc() {
            return Err(Error::InvalidPrices);
        } else if !host_key.verify(prices.sig_hash().as_ref(), &prices.signature) {
            return Err(Error::InvalidSignature);
        }
        self.set_cached_prices(&host_key, prices.clone());
        Ok(prices)
    }
}

#[derive(Debug)]
struct DialerInner {
    /*
        note: quinn's documentation (https://docs.rs/quinn/latest/quinn/struct.Endpoint.html#method.client) suggests
        non-ideal fallback behavior when dual-stack is not supported. This effectively treats every platform as
        single-stack instead since IPv4 is the preferred fallback.
    */
    endpoint_v4: Option<Endpoint>,
    endpoint_v6: Option<Endpoint>,

    hosts: Mutex<HashMap<PublicKey, Vec<NetAddress>>>,
    open_conns: Mutex<HashMap<PublicKey, Connection>>,
    cached_prices: Mutex<HashMap<PublicKey, HostPrices>>,
}

impl DialerInner {
    fn new(mut client_config: ClientConfig) -> Result<Self, Error> {
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
            open_conns: Mutex::new(HashMap::new()),
            cached_prices: Mutex::new(HashMap::new()),
        })
    }
}

impl HostDialer for Dialer {
    type Error = Error;

    async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: &[u8],
    ) -> Result<Hash256, Self::Error> {
        let prices = self.host_prices(host_key, false).await?;
        let token = AccountToken::new(account_key, host_key);
        let stream = self.host_stream(host_key).await?;
        let resp = RPCWriteSector::send_request(stream, prices, token, sector.to_vec())
            .await?
            .complete()
            .await?;
        Ok(resp.root)
    }

    async fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        let prices = self.host_prices(host_key, false).await?;
        let token = AccountToken::new(account_key, host_key);
        let stream = self.host_stream(host_key).await?;
        let resp = RPCReadSector::send_request(stream, prices, token, root, offset, limit)
            .await?
            .complete()
            .await?;
        Ok(resp.data)
    }

    fn hosts(&self) -> Vec<PublicKey> {
        self.inner.hosts.lock().unwrap().keys().cloned().collect()
    }

    fn update_hosts(&mut self, hosts: Vec<Host>) {
        let mut hosts_map = self.inner.hosts.lock().unwrap();
        hosts_map.clear();
        for host in hosts {
            hosts_map.insert(host.public_key, host.addresses);
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;
    use crate::public_key;
    use rustls_platform_verifier::ConfigVerifierExt;
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

        let mut dialer = Dialer::new(client_config).expect("Failed to create dialer");
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
