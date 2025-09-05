use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::debug;
use thiserror::{self, Error};
use time::OffsetDateTime;
use tokio::time::error::Elapsed;
use tokio::time::timeout;
use web_transport::{ClientBuilder, Session};

use crate::encoding_async::AsyncDecoder;
use crate::objects::HostDialer;
use crate::rhp::{
    self, AccountToken, Host, HostPrices, RPCReadSector, RPCSettings, RPCWriteSector, Transport,
};
use crate::signing::{PrivateKey, PublicKey};
use crate::types::Hash256;
use crate::types::v2::{NetAddress, Protocol};
use crate::{encoding, objects};

const DEFAULT_BUFFER_SIZE: usize = 8 * 1024;

struct Stream {
    send: web_transport::SendStream,
    recv: web_transport::RecvStream,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to connect")]
    FailedToConnect,

    #[error("encoding error: {0}")]
    Encoding(#[from] encoding::Error),

    #[error("invalid prices")]
    InvalidPrices,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("object error: {0}")]
    Object(#[from] objects::Error),

    #[error("url parse error: {0}")]
    Parse(#[from] url::ParseError),

    #[error("rhp error: {0}")]
    RHP(#[from] rhp::Error),

    #[error("stream was closed")]
    StreamClosed,

    #[error("timeout error: {0}")]
    Timeout(#[from] Elapsed),

    #[error("unknown host: {0}")]
    UnknownHost(PublicKey),

    #[error("web-transport error: {0}")]
    WebTransport(#[from] web_transport::Error),
}

impl AsyncDecoder for Stream {
    type Error = Error;
    async fn decode_buf(&mut self, mut buf: &mut [u8]) -> Result<(), Self::Error> {
        while !buf.is_empty() {
            if let Some(n) = self.recv.read_buf(&mut buf).await? {
                buf = &mut buf[n..];
            } else {
                return Err(Error::StreamClosed);
            }
        }
        Ok(())
    }
}

impl Transport for Stream {
    type Error = Error;

    async fn write_request<R: rhp::RPCRequest>(&mut self, req: &R) -> Result<(), Self::Error> {
        let mut buf = Vec::with_capacity(DEFAULT_BUFFER_SIZE);
        req.encode_request(&mut buf).await?;
        self.send.write(&buf[..]).await?;
        Ok(())
    }

    async fn read_response<R: rhp::RPCResponse>(&mut self) -> Result<R, Self::Error> {
        R::decode_response(self).await
    }

    async fn write_response<RR: rhp::RPCResponse>(&mut self, resp: &RR) -> Result<(), Self::Error> {
        let mut buf = Vec::with_capacity(DEFAULT_BUFFER_SIZE);
        resp.encode_response(&mut buf).await?;
        self.send.write(&buf[..]).await?;
        Ok(())
    }
}

pub struct Dialer {
    inner: Arc<DialerInner>,
}

impl Dialer {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            inner: Arc::new(DialerInner::new()?),
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

    fn existing_session(&self, host: PublicKey) -> Option<Session> {
        let open_sessions = self.inner.open_sessions.lock().unwrap();
        if let Some(session) = open_sessions.get(&host) {
            return Some(session.clone());
        }
        None
    }

    async fn track_session_closed(dialer: Arc<DialerInner>, host: PublicKey, session: Session) {
        let _ = session.closed().await;
        dialer.open_sessions.lock().unwrap().remove(&host);
    }

    async fn new_session(&self, host: PublicKey) -> Result<Session, Error> {
        let addresses = {
            let hosts = self.inner.hosts.lock().unwrap();
            hosts.get(&host).cloned().ok_or(Error::UnknownHost(host))?
        };
        for addr in addresses {
            if addr.protocol != Protocol::QUIC {
                continue;
            }

            let session = self.inner.client.connect(addr.address.parse()?).await?;
            tokio::spawn({
                let dialer = self.inner.clone();
                Self::track_session_closed(dialer, host, session.clone())
            });
            return Ok(session);
        }
        Err(Error::FailedToConnect)
    }

    async fn host_stream(&self, host: PublicKey) -> Result<Stream, Error> {
        let mut session = if let Some(session) = self.existing_session(host) {
            debug!("reusing existing session to {host}");
            session
        } else {
            debug!("establishing new session to {host}");
            let new_session = timeout(Duration::from_secs(30), self.new_session(host)).await??;
            let open_sessions = &mut self.inner.open_sessions.lock().unwrap();
            open_sessions.insert(host, new_session.clone());
            debug!("established new session to {host}");
            new_session
        };

        let (send, recv) = session.open_bi().await?;
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
        debug!("fetching prices for {host_key}");
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
}

struct DialerInner {
    client: web_transport::Client,
    hosts: Mutex<HashMap<PublicKey, Vec<NetAddress>>>,
    open_sessions: Mutex<HashMap<PublicKey, Session>>,
    cached_prices: Mutex<HashMap<PublicKey, HostPrices>>,
}

impl DialerInner {
    fn new() -> Result<Self, Error> {
        let client = ClientBuilder::new().with_system_roots()?;
        Ok(Self {
            client,
            hosts: Mutex::new(HashMap::new()),
            open_sessions: Mutex::new(HashMap::new()),
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
        sector: Bytes,
    ) -> Result<Hash256, Self::Error> {
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

    async fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, Self::Error> {
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
