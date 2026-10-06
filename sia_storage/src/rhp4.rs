use std::ops::Range;

use bytes::Bytes;
use sia_core::encoding;
use sia_core::rhp4::protocol::Error as RHP4Error;
use sia_core::rhp4::{AccountToken, HostPrices};
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;
use sia_core::types::v2::NetAddress;
use thiserror::Error;

use crate::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
mod siamux;

#[cfg(target_arch = "wasm32")]
mod web_transport;

#[cfg(any(test, feature = "mock"))]
pub(crate) mod mock;

/// The transport used to talk to hosts. One real backend exists per
/// target. The `mock` feature adds an in-memory backend alongside it.
#[derive(Clone)]
pub(crate) enum Client {
    #[cfg(not(target_arch = "wasm32"))]
    SiaMux(siamux::Client),
    #[cfg(target_arch = "wasm32")]
    WebTransport(web_transport::Client),
    #[cfg(any(test, feature = "mock"))]
    Mock(mock::Client),
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Creates a client using the real transport for this target.
    pub(crate) fn new() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Self::SiaMux(siamux::Client::new())
        }
        #[cfg(target_arch = "wasm32")]
        {
            Self::WebTransport(web_transport::Client::new())
        }
    }

    /// Creates a client backed by the in-memory mock transport. Use
    /// [`Client::Mock`] directly when the test needs to keep the
    /// [`mock::Client`] handle to seed sectors or add latency.
    #[cfg(test)]
    pub(crate) fn mock() -> Self {
        Self::Mock(mock::Client::new())
    }
}

impl Transport for Client {
    async fn host_prices(
        &self,
        host: &HostEndpoint,
        idle_timeout: Duration,
    ) -> Result<(HostPrices, Duration), Error> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Self::SiaMux(c) => c.host_prices(host, idle_timeout).await,
            #[cfg(target_arch = "wasm32")]
            Self::WebTransport(c) => c.host_prices(host, idle_timeout).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.host_prices(host, idle_timeout).await,
        }
    }

    async fn write_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        sector: Bytes,
        idle_timeout: Duration,
    ) -> Result<(Hash256, Duration), Error> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Self::SiaMux(c) => {
                c.write_sector(host, prices, account_key, sector, idle_timeout)
                    .await
            }
            #[cfg(target_arch = "wasm32")]
            Self::WebTransport(c) => {
                c.write_sector(host, prices, account_key, sector, idle_timeout)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => {
                c.write_sector(host, prices, account_key, sector, idle_timeout)
                    .await
            }
        }
    }

    async fn read_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        token: AccountToken,
        root: Hash256,
        range: Range<usize>,
        idle_timeout: Duration,
    ) -> Result<(Bytes, Duration), Error> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Self::SiaMux(c) => {
                c.read_sector(host, prices, token, root, range, idle_timeout)
                    .await
            }
            #[cfg(target_arch = "wasm32")]
            Self::WebTransport(c) => {
                c.read_sector(host, prices, token, root, range, idle_timeout)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => {
                c.read_sector(host, prices, token, root, range, idle_timeout)
                    .await
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encoding error: {0}")]
    Encoding(#[from] encoding::Error),

    #[error("rhp error: {0}")]
    Rpc(#[from] RHP4Error),

    #[error("invalid prices")]
    InvalidPrices,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("transport error: {0}")]
    Transport(String),
}

impl Error {
    /// Whether the RPC's stream went idle. Both transports report a stalled
    /// stream as an I/O error of kind [`std::io::ErrorKind::TimedOut`].
    pub(crate) fn is_timeout(&self) -> bool {
        matches!(
            self,
            Error::Io(e) | Error::Rpc(RHP4Error::Io(e))
                if e.kind() == std::io::ErrorKind::TimedOut
        )
    }
}

/// A host endpoint contains the information needed to connect to a host.
// dead code until WebTransport client is implemented
pub(crate) struct HostEndpoint {
    pub public_key: PublicKey,
    pub addresses: Vec<NetAddress>,
}

/// Trait defining the operations that can be performed on a host.
///
/// Each RPC returns the on-wire duration of the RPC alongside its result. The
/// duration measures only the time spent exchanging request/response bytes —
/// it excludes connection setup and stream opening. Callers can feed it into
/// host performance tracking without contamination from pool-miss costs.
///
/// Each RPC takes an `idle_timeout`: the longest its stream may go without
/// making progress in either direction before the RPC fails with an I/O
/// error of kind [`std::io::ErrorKind::TimedOut`] (see [`Error::is_timeout`]).
/// There is no bound on the total RPC duration, so a slow transfer that keeps
/// moving bytes is allowed to finish.
pub(crate) trait Transport: Clone + Unpin + MaybeSendSync + 'static {
    fn host_prices(
        &self,
        host: &HostEndpoint,
        idle_timeout: Duration,
    ) -> impl Future<Output = Result<(HostPrices, Duration), Error>> + MaybeSendSync;
    fn write_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        sector: Bytes,
        idle_timeout: Duration,
    ) -> impl Future<Output = Result<(Hash256, Duration), Error>> + MaybeSendSync;
    fn read_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        token: AccountToken,
        root: Hash256,
        range: Range<usize>,
        idle_timeout: Duration,
    ) -> impl Future<Output = Result<(Bytes, Duration), Error>> + MaybeSendSync;
}
#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait MaybeSendSync: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> MaybeSendSync for T {}

#[cfg(target_arch = "wasm32")]
pub(crate) trait MaybeSendSync {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSendSync for T {}
