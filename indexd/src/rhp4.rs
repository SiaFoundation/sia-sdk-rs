use async_trait::async_trait;
use bytes::Bytes;
use sia::encoding;
use sia::rhp::{self, HostPrices};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use thiserror::Error;
use tokio::time::error::Elapsed;

#[derive(Debug, Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encoding error: {0}")]
    Encoding(#[from] encoding::Error),

    #[error("rhp error: {0}")]
    Rhp(#[from] rhp::Error),

    #[error("invalid prices")]
    InvalidPrices,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("timeout error: {0}")]
    Timeout(#[from] Elapsed),

    #[error("transport error: {0}")]
    Transport(String),
}

/// Trait defining the operations that can be performed on a host.
#[async_trait]
pub(crate) trait RHP4Client: Send + Sync {
    async fn host_prices(&self, host_key: PublicKey, refresh: bool) -> Result<HostPrices, Error>;
    async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> Result<Hash256, Error>;
    async fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, Error>;
}
