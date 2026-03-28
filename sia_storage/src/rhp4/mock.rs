use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::rhp4::{Error, HostEndpoint, Transport};
use crate::time::{Duration, sleep};
use bytes::Bytes;
use chrono::Utc;
use sia_core::rhp4::HostPrices;
use sia_core::signing::{PrivateKey, PublicKey, Signature};
use sia_core::types::{Currency, Hash256};

struct ClientInner {
    sectors: RwLock<HashMap<PublicKey, HashMap<Hash256, Bytes>>>,
    slow_hosts: RwLock<HashSet<PublicKey>>,
    slow_delay: RwLock<Duration>,
}

#[derive(Clone)]
pub(crate) struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ClientInner {
                sectors: RwLock::new(HashMap::new()),
                slow_hosts: RwLock::new(HashSet::new()),
                slow_delay: RwLock::new(Duration::ZERO),
            }),
        }
    }

    pub fn clear(&self) {
        self.inner.sectors.write().unwrap().clear();
    }

    /// Sets the given hosts as "slow" - they will sleep for the specified duration
    /// before completing any write_sector or read_sector operation.
    pub fn set_slow_hosts(&self, hosts: impl IntoIterator<Item = PublicKey>, delay: Duration) {
        let mut slow = self.inner.slow_hosts.write().unwrap();
        slow.clear();
        slow.extend(hosts);
        *self.inner.slow_delay.write().unwrap() = delay;
    }

    /// Clears all slow host settings.
    pub fn reset_slow_hosts(&self) {
        self.inner.slow_hosts.write().unwrap().clear();
        *self.inner.slow_delay.write().unwrap() = Duration::ZERO;
    }
}

impl Transport for Client {
    async fn host_prices(&self, _: &HostEndpoint) -> Result<HostPrices, Error> {
        Ok(HostPrices {
            contract_price: Currency::zero(),
            collateral: Currency::zero(),
            ingress_price: Currency::zero(),
            egress_price: Currency::zero(),
            storage_price: Currency::zero(),
            free_sector_price: Currency::zero(),
            tip_height: 1,
            signature: Signature::default(),
            valid_until: Utc::now() + chrono::Duration::days(1),
        })
    }

    async fn write_sector(
        &self,
        host: &HostEndpoint,
        _: HostPrices,
        _: &PrivateKey,
        sector: Bytes,
    ) -> Result<Hash256, Error> {
        // Check if this host is configured as slow
        let slow_delay = {
            let slow_hosts = self.inner.slow_hosts.read().unwrap();
            if slow_hosts.contains(&host.public_key) {
                Some(*self.inner.slow_delay.read().unwrap())
            } else {
                None
            }
        };
        let host_key = host.public_key;
        let inner = self.inner.clone();
        tokio::spawn(async move {
            if let Some(delay) = slow_delay {
                sleep(delay).await;
            }

            sleep(Duration::from_millis(3)).await; // simulate network latency ~ 10Gbps
            let sector_root = sia_core::rhp4::sector_root(&sector);
            let mut sectors = inner.sectors.write().unwrap();
            let host_sectors = sectors.entry(host_key).or_default();
            host_sectors.insert(sector_root, sector);
            Ok(sector_root)
        })
        .await
        .unwrap()
    }

    async fn read_sector(
        &self,
        host: &HostEndpoint,
        _: HostPrices,
        _: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, Error> {
        // Check if this host is configured as slow
        let slow_delay = {
            let slow_hosts = self.inner.slow_hosts.read().unwrap();
            if slow_hosts.contains(&host.public_key) {
                Some(*self.inner.slow_delay.read().unwrap())
            } else {
                None
            }
        };
        let host_key = host.public_key;
        let inner = self.inner.clone();
        tokio::spawn(async move {
            if let Some(delay) = slow_delay {
                sleep(delay).await;
            }

            let sector = {
                let sectors = inner.sectors.read().unwrap();
                let host_sectors = sectors
                    .get(&host_key)
                    .ok_or_else(|| Error::Transport("host not found".to_string()))?;
                let sector = host_sectors
                    .get(&root)
                    .ok_or_else(|| Error::Transport("sector not found".to_string()))?;
                Bytes::copy_from_slice(&sector[offset..offset + length])
            };
            sleep(Duration::from_nanos(sector.len() as u64 * 8 / 10)).await; // simulate network latency ~ 10Gbps
            Ok(sector)
        })
        .await
        .unwrap()
    }
}
