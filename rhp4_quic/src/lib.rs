use quinn::crypto::rustls::QuicClientConfig;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::num::ParseIntError;
use std::sync::Arc;
use thiserror::{self, Error};

use quinn::{Connection, Endpoint, RecvStream, SendStream};
use sia::encoding::Error as EncodingError;
use sia::encoding_async::{AsyncDecoder, AsyncEncoder, Result as EncodingResult};
use sia::rhp::{
    AccountToken, Error as RHPError, Host, HostPrices, RPCReadSector, RPCSettings, RPCWriteSector,
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

impl AsyncDecoder for Stream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> EncodingResult<()> {
        self.recv
            .read_exact(buf)
            .await
            .map_err(|e| EncodingError::Custom(e.to_string()))
    }
}

impl AsyncEncoder for Stream {
    async fn write_all(&mut self, buf: &[u8]) -> EncodingResult<()> {
        self.send
            .write_all(buf)
            .await
            .map_err(|e| EncodingError::Custom(e.to_string()))
    }
}

/// A Dialer manages QUIC connections to Sia hosts.
/// Connections will be cached for reuse whenever possible.
#[derive(Debug)]
pub struct Dialer {
    /*
        note: quinn's documentation (https://docs.rs/quinn/latest/quinn/struct.Endpoint.html#method.client) suggests
        non-ideal fallback behavior when dual-stack is not supported. This effectively treats every platform as
        single-stack instead since IPv4 is the preferred fallback.
    */
    endpoint_v4: Endpoint,
    endpoint_v6: Option<Endpoint>,

    hosts: Mutex<HashMap<PublicKey, Vec<NetAddress>>>,
    open_conns: Mutex<HashMap<PublicKey, Connection>>,
    cached_prices: Mutex<HashMap<PublicKey, HostPrices>>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("rhp error: {0}")]
    RHP(#[from] RHPError),

    #[error("unknown host: {0}")]
    UnknownHost(PublicKey),

    #[error("invalid port: {0}")]
    InvalidPort(#[from] ParseIntError),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid prices")]
    InvalidPrices,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("connection failed")]
    ConnectionFailed,
}

impl Dialer {
    pub fn new(mut client_config: ClientConfig) -> Self {
        client_config.alpn_protocols = vec![b"sia/rhp4".to_vec()];

        let client_config = QuicClientConfig::try_from(client_config).unwrap();
        let client_config = quinn::ClientConfig::new(Arc::new(client_config));

        let mut endpoint_v4 = quinn::Endpoint::client((Ipv4Addr::UNSPECIFIED, 0).into()).unwrap();
        endpoint_v4.set_default_client_config(client_config.clone());

        let endpoint_v6 = match quinn::Endpoint::client((Ipv6Addr::UNSPECIFIED, 0).into()) {
            Ok(mut endpoint) => {
                endpoint.set_default_client_config(client_config);
                Some(endpoint)
            }
            Err(_) => None,
        };

        Self {
            endpoint_v4,
            endpoint_v6,
            hosts: Mutex::new(HashMap::new()),
            open_conns: Mutex::new(HashMap::new()),
            cached_prices: Mutex::new(HashMap::new()),
        }
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

    async fn dial_host(&mut self, host: PublicKey) -> Result<Stream, Error> {
        let existing_conn = {
            let open_conns = self.open_conns.lock().unwrap();
            open_conns.get(&host).cloned()
        };
        let conn = if let Some(existing_conn) = existing_conn
            && existing_conn.close_reason().is_none()
        {
            existing_conn
        } else {
            let addresses = {
                let hosts = self.hosts.lock().unwrap();
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
                        && let Some(endpoint) = &self.endpoint_v6
                    {
                        let conn = endpoint.connect(socket, addr).unwrap().await.ok();
                        if let Some(conn) = conn {
                            new_conn = Some(conn);
                            break;
                        }
                    } else if socket.is_ipv4() {
                        let conn = self.endpoint_v4.connect(socket, addr).unwrap().await.ok();
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

            let conn = new_conn.ok_or(Error::ConnectionFailed)?;
            let open_conns = &mut self.open_conns.lock().unwrap();
            open_conns.insert(host, conn.clone());
            conn
        };

        let (send, recv) = conn
            .open_bi()
            .await
            .expect("Failed to open bidirectional stream");
        Ok(Stream { send, recv })
    }

    pub async fn set_hosts(&mut self, hosts: Vec<Host>) {
        let mut host_map = self.hosts.lock().unwrap();
        for host in hosts {
            host_map.insert(host.public_key, host.addresses);
        }
    }

    pub async fn host_prices(
        &mut self,
        host_key: PublicKey,
        refresh: bool,
    ) -> Result<HostPrices, Error> {
        if !refresh && let Some(prices) = self.get_cached_prices(&host_key) {
            return Ok(prices);
        }

        let stream = self.dial_host(host_key).await?;
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

    pub async fn write_sector(
        &mut self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Vec<u8>,
    ) -> Result<Hash256, Error> {
        let prices = self.host_prices(host_key, false).await?;
        let stream = self.dial_host(host_key).await?;
        let token = AccountToken::new(account_key, host_key);

        let resp = RPCWriteSector::send_request(stream, prices, token, sector)
            .await?
            .complete()
            .await?;

        Ok(resp.root)
    }

    pub async fn read_sector(
        &mut self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<u8>, Error> {
        let prices = self.host_prices(host_key, false).await?;
        let stream = self.dial_host(host_key).await?;
        let token = AccountToken::new(account_key, host_key);

        let resp = RPCReadSector::send_request(stream, prices, token, root, offset, limit)
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

        let mut dialer = Dialer::new(client_config);
        dialer
            .set_hosts(vec![Host {
                public_key: host_key,
                addresses: vec![NetAddress {
                    protocol: Protocol::QUIC,
                    address: "6r4b0vj1ai55fobdvauvpg3to5bpeijl045b2q268fcj7q1vkuog.sia.host:9984"
                        .into(),
                }],
            }])
            .await;

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
