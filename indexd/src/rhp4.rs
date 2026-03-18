use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use sia::encoding;
use sia::rhp::{self, HostPrices};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use thiserror::Error;
use tokio::time::error::Elapsed;

use crate::Hosts;

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

/// An RHP4Client that declares which protocol(s) it supports.
/// Used by `MultiTransport` to route host connections to the
/// appropriate transport based on the host's advertised addresses.
pub(crate) trait RHP4Transport: RHP4Client {
    fn supported_protocols(&self) -> &[&str];
}

/// A composite transport that routes RHP4 calls to the appropriate transport
/// based on the host's advertised protocol strings.
pub(crate) struct MultiTransport {
    hosts: Hosts,
    transports: Vec<Arc<dyn RHP4Transport>>,
}

impl MultiTransport {
    /// Creates a new MultiTransport. The order of `transports` determines
    /// protocol preference — earlier transports are tried first when a host
    /// advertises multiple protocols. For example, `vec![quic, siamux]`
    /// will prefer QUIC over siamux when a host supports both.
    pub fn new(hosts: Hosts, transports: Vec<Arc<dyn RHP4Transport>>) -> Self {
        Self { hosts, transports }
    }

    /// Returns all registered transports that support at least one of the
    /// host's advertised protocols, ordered by registration preference.
    fn transports_for_host(&self, host_key: &PublicKey) -> Result<Vec<&dyn RHP4Transport>, Error> {
        let addresses = self
            .hosts
            .addresses(host_key)
            .ok_or_else(|| Error::Transport("unknown host".into()))?;
        let mut result = Vec::new();
        for t in &self.transports {
            for addr in &addresses {
                if t.supported_protocols().contains(&addr.protocol.as_str()) {
                    result.push(t.as_ref());
                    break;
                }
            }
        }
        if result.is_empty() {
            return Err(Error::Transport(
                "no transport supports this host's protocols".into(),
            ));
        }
        Ok(result)
    }
}

#[async_trait]
impl RHP4Client for MultiTransport {
    async fn host_prices(&self, host_key: PublicKey, refresh: bool) -> Result<HostPrices, Error> {
        let transports = self.transports_for_host(&host_key)?;
        let mut last_err = Error::Transport("all transports failed".into());
        for t in transports {
            match t.host_prices(host_key, refresh).await {
                Ok(prices) => return Ok(prices),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> Result<Hash256, Error> {
        let transports = self.transports_for_host(&host_key)?;
        let mut last_err = Error::Transport("all transports failed".into());
        for t in transports {
            match t.write_sector(host_key, account_key, sector.clone()).await {
                Ok(root) => return Ok(root),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, Error> {
        let transports = self.transports_for_host(&host_key)?;
        let mut last_err = Error::Transport("all transports failed".into());
        for t in transports {
            match t
                .read_sector(host_key, account_key, root, offset, length)
                .await
            {
                Ok(data) => return Ok(data),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sia::rhp::Host;
    use sia::signing::Signature;
    use sia::types::Currency;
    use sia::types::v2::{NetAddress, Protocol};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A configurable mock transport for testing MultiTransport routing.
    struct MockTransport {
        protocols: Vec<&'static str>,
        should_fail: bool,
        /// Incremented each time an RPC method is called.
        call_count: AtomicUsize,
        /// Unique identifier to distinguish which transport was used.
        id: u64,
    }

    impl MockTransport {
        fn new(protocols: Vec<&'static str>, should_fail: bool, id: u64) -> Self {
            Self {
                protocols,
                should_fail,
                call_count: AtomicUsize::new(0),
                id,
            }
        }

        fn calls(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    impl RHP4Transport for MockTransport {
        fn supported_protocols(&self) -> &[&str] {
            &self.protocols
        }
    }

    #[async_trait]
    impl RHP4Client for MockTransport {
        async fn host_prices(&self, _: PublicKey, _: bool) -> Result<HostPrices, Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                return Err(Error::Transport(format!("mock {} failed", self.id)));
            }
            Ok(HostPrices {
                contract_price: Currency::zero(),
                collateral: Currency::zero(),
                ingress_price: Currency::zero(),
                egress_price: Currency::zero(),
                storage_price: Currency::zero(),
                free_sector_price: Currency::zero(),
                tip_height: self.id,
                signature: Signature::default(),
                valid_until: chrono::Utc::now() + chrono::Duration::days(1),
            })
        }

        async fn write_sector(
            &self,
            _: PublicKey,
            _: &PrivateKey,
            _: Bytes,
        ) -> Result<Hash256, Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                return Err(Error::Transport(format!("mock {} failed", self.id)));
            }
            Ok(Hash256::default())
        }

        async fn read_sector(
            &self,
            _: PublicKey,
            _: &PrivateKey,
            _: Hash256,
            _: usize,
            length: usize,
        ) -> Result<Bytes, Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                return Err(Error::Transport(format!("mock {} failed", self.id)));
            }
            Ok(Bytes::from(vec![0u8; length]))
        }
    }

    fn test_host_key() -> PublicKey {
        PrivateKey::from_seed(&[1u8; 32]).public_key()
    }

    fn hosts_with_protocols(host_key: PublicKey, protocols: Vec<Protocol>) -> Hosts {
        let hosts = Hosts::new();
        hosts.update(vec![Host {
            public_key: host_key,
            addresses: protocols
                .into_iter()
                .map(|p| NetAddress {
                    protocol: p,
                    address: "localhost:1234".to_string(),
                })
                .collect(),
            country_code: "US".to_string(),
            latitude: 0.0,
            longitude: 0.0,
            good_for_upload: true,
        }]);
        hosts
    }

    #[tokio::test]
    async fn falls_back_on_failure() {
        let host_key = test_host_key();
        let hosts = hosts_with_protocols(host_key, vec![Protocol::SiaMux, Protocol::QUIC]);

        let siamux = Arc::new(MockTransport::new(vec!["siamux"], true, 1));
        let quic = Arc::new(MockTransport::new(vec!["quic"], false, 2));

        let mt = MultiTransport::new(hosts, vec![siamux.clone(), quic.clone()]);
        let prices = mt.host_prices(host_key, false).await.unwrap();

        assert_eq!(prices.tip_height, 2);
        assert_eq!(siamux.calls(), 1);
        assert_eq!(quic.calls(), 1);
    }

    #[tokio::test]
    async fn no_matching_protocol() {
        let host_key = test_host_key();
        let hosts = hosts_with_protocols(host_key, vec![Protocol::SiaMux]);

        let quic = Arc::new(MockTransport::new(vec!["quic"], false, 1));

        let mt = MultiTransport::new(hosts, vec![quic]);
        let err = mt.host_prices(host_key, false).await.unwrap_err();

        assert!(
            err.to_string()
                .contains("no transport supports this host's protocols")
        );
    }
}
