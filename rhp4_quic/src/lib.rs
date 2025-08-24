use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;
use std::{collections::HashMap, net::ToSocketAddrs, sync::Arc};
use thiserror::{self, Error};

use quinn::{crypto::rustls::QuicClientConfig, Connection, Endpoint, RecvStream, SendStream};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use sia::encoding::Error as EncodingError;
use sia::rhp::{AccountToken, Error as RHPError, Host, RPCReadSector, RPCSettings, RPCWriteSector};
use sia::signing::PrivateKey;
use sia::{encoding_async::{AsyncDecoder, AsyncEncoder, Result as EncodingResult}, rhp::HostPrices, signing::PublicKey, types::{v2::{NetAddress, Protocol}, Hash256}};

struct Stream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncDecoder for Stream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> EncodingResult<()> {
        self.recv.read_exact(buf).await.map_err(|e| {
            EncodingError::Io(e.to_string())
        })
    }
}

impl AsyncEncoder for Stream {
    async fn write_all(&mut self, buf: &[u8]) -> EncodingResult<()> {
        self.send.write_all(buf).await.map_err(|e| {
            EncodingError::Io(e.to_string())
        })
    }
}

/// A Dialer manages QUIC connections to Sia hosts.
/// Connections will be cached for reuse whenever possible.
#[derive(Debug)]
pub struct Dialer {
    // note: quinn's documentation suggests non-ideal fallback behavior 
    // when dual-stack is not supported. This effectively treats 
    // every platform as single-stack instead since IPv4 is the
    // preferred fallback.
    endpoint_v4: Endpoint,
    endpoint_v6: Option<Endpoint>,

    hosts: Mutex<HashMap<PublicKey, Vec<NetAddress>>>,
    open_conns: Mutex<HashMap<PublicKey, Connection>>,
    cached_prices: Mutex<HashMap<PublicKey, HostPrices>>
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
    ConnectionFailed
}

impl Dialer {
    pub fn new() -> Self {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            rustls::crypto::ring::default_provider()
                .install_default().unwrap();
        }
        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();

        client_crypto.alpn_protocols = vec![b"sia/rhp4".to_vec()];

        let client_config = QuicClientConfig::try_from(client_crypto).unwrap();
        let client_config =
            quinn::ClientConfig::new(Arc::new(client_config));

        let mut endpoint_v4 = quinn::Endpoint::client((Ipv4Addr::UNSPECIFIED, 0).into()).unwrap();
        endpoint_v4.set_default_client_config(client_config.clone());

        let endpoint_v6 = match quinn::Endpoint::client((Ipv6Addr::UNSPECIFIED, 0).into()) {
            Ok(mut endpoint) => {
                endpoint.set_default_client_config(client_config.clone());
                Some(endpoint)
            },
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

    async fn dial_host(&mut self, host: PublicKey) -> Result<Stream, Error> {
        let mut open_conns = self.open_conns.lock().await;
        let conn = if let Some(existing_conn) = open_conns.get(&host) && existing_conn.close_reason().is_none() {
            existing_conn.clone()
        } else {
            let hosts = self.hosts.lock().await;
            let addresses = hosts.get(&host).ok_or(Error::UnknownHost(host))?;
            let mut new_conn = None;
            for addr in addresses {
                    if addr.protocol != Protocol::QUIC {
                        continue;
                    }
                    let (addr, port_str) = addr.address.rsplit_once(':').ok_or(Error::InvalidAddress(addr.address.clone()))?;
                    let port: u16 = port_str.parse()?;
                    let resolved_addrs = (addr, port).to_socket_addrs()?;
                    for socket in resolved_addrs {
                        if socket.is_ipv6() && let Some(endpoint) = &self.endpoint_v6 {
                            let conn = endpoint.connect(socket, addr)
                                .unwrap()
                                .await
                                .ok();
                            if let Some(conn) = conn {
                                new_conn = Some(conn);
                                break;
                            }
                        } else if socket.is_ipv4() {
                            let conn = self.endpoint_v4.connect(socket, addr)
                                .unwrap()
                                .await
                                .ok();
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
            open_conns.insert(host, conn.clone());
            conn
        };

        let (send, recv) = conn.open_bi().await.expect("Failed to open bidirectional stream");
        Ok(Stream { send, recv })
    }

    pub async fn set_hosts(&mut self, hosts: Vec<Host>) {
        let mut host_map = self.hosts.lock().await;
        for host in hosts {
            host_map.insert(host.public_key, host.addresses);
        }
    }

    pub async fn host_prices(&mut self, host_key: PublicKey, refresh: bool) -> Result<HostPrices, Error> {
        if self.hosts.lock().await.get(&host_key).is_none() {
            return Err(Error::UnknownHost(host_key));
        }

        if !refresh && let Some(prices) = self.cached_prices.lock().await.get(&host_key) {
            if prices.valid_until < OffsetDateTime::now_utc() {
                self.cached_prices.lock().await.remove(&host_key);
            } else {
                return Ok(prices.clone());
            }
        }

        let stream = self.dial_host(host_key).await?;
        let resp = RPCSettings::send_request(stream).await?
            .complete().await?;
        let prices = resp.settings.prices;
        if prices.valid_until < OffsetDateTime::now_utc() {
            return Err(Error::InvalidPrices);
        } else if !host_key.verify(prices.sig_hash().as_ref(), &prices.signature) {
            return Err(Error::InvalidSignature);
        }
        self.cached_prices.lock().await.insert(host_key, prices.clone());
        Ok(prices)
    }

    pub async fn write_sector(&mut self, host_key: PublicKey, account_key: &PrivateKey, sector: Vec<u8>) -> Result<Hash256, Error> {
        let prices = self.host_prices(host_key, false).await?;
        let stream = self.dial_host(host_key).await?;
        let token = AccountToken::new(account_key, host_key);

        let resp = RPCWriteSector::send_request(stream, prices, token, sector).await?
            .complete().await?;

        Ok(resp.root)
    }

    pub async fn read_sector(&mut self, host_key: PublicKey, account_key: &PrivateKey, root: Hash256, offset: usize, limit: usize) -> Result<Vec<u8>, Error> {
        let prices = self.host_prices(host_key, false).await?;
        let stream = self.dial_host(host_key).await?;
        let token = AccountToken::new(account_key, host_key);

        let resp = RPCReadSector::send_request(stream, prices, token, root, offset, limit).await?
            .complete().await?;

        Ok(resp.data)
    }
}


#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
} 