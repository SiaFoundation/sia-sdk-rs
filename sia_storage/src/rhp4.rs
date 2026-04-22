use bytes::Bytes;
use sia_core::encoding;
use sia_core::rhp4::HostPrices;
use sia_core::rhp4::protocol::Error as RHP4Error;
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;
use sia_core::types::v2::NetAddress;
use thiserror::Error;

use crate::time::{Duration, Elapsed};

#[cfg(not(any(test, feature = "mock", target_arch = "wasm32")))]
mod siamux;

#[cfg(not(any(test, feature = "mock", target_arch = "wasm32")))]
pub use siamux::Client;

#[cfg(all(not(test), not(feature = "mock"), target_arch = "wasm32"))]
mod web_transport;

#[cfg(all(not(test), not(feature = "mock"), target_arch = "wasm32"))]
pub use web_transport::Client;

#[cfg(any(test, feature = "mock"))]
mod mock;

#[cfg(any(test, feature = "mock"))]
pub use mock::Client;

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

    #[error("timeout error: {0}")]
    Timeout(#[from] Elapsed),

    #[error("transport error: {0}")]
    Transport(String),
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
pub(crate) trait Transport: Clone + Unpin + MaybeSendSync + 'static {
    fn host_prices(
        &self,
        host: &HostEndpoint,
    ) -> impl Future<Output = Result<(HostPrices, Duration), Error>> + MaybeSendSync;
    fn write_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> impl Future<Output = Result<(Hash256, Duration), Error>> + MaybeSendSync;
    fn read_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
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
