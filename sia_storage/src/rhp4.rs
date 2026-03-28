use bytes::Bytes;
use sia_core::encoding;
use sia_core::rhp4::HostPrices;
use sia_core::rhp4::protocol::Error as RHP4Error;
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;
use sia_core::types::v2::NetAddress;
use thiserror::Error;

use crate::time::Elapsed;

#[cfg(all(not(feature = "mock"), not(target_arch = "wasm32")))]
mod siamux;
#[cfg(all(not(feature = "mock"), not(target_arch = "wasm32")))]
pub(crate) use siamux::Client;

#[cfg(all(not(feature = "mock"), target_arch = "wasm32"))]
mod web_transport;

#[cfg(all(not(feature = "mock"), target_arch = "wasm32"))]
pub(crate) use web_transport::Client;

#[cfg(feature = "mock")]
mod mock;
#[cfg(feature = "mock")]
pub(crate) use mock::Client;

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
pub(crate) struct HostEndpoint {
    pub public_key: PublicKey,
    pub addresses: Vec<NetAddress>,
}

/// Trait defining the operations that can be performed on a host
pub(crate) trait Transport {
    fn host_prices(&self, host: &HostEndpoint) -> impl Future<Output = Result<HostPrices, Error>>;
    fn write_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> impl Future<Output = Result<Hash256, Error>>;
    fn read_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> impl Future<Output = Result<Bytes, Error>>;
}
