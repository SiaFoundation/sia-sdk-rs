use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use chrono::Utc;
use sia_core::rhp4::HostPrices;
use sia_core::signing::{PrivateKey, PublicKey, Signature};
use sia_core::types::{Currency, Hash256};

use super::{Error as RHP4Error, HostEndpoint, Transport};
use crate::time::{Duration, sleep};

#[derive(Clone)]
pub struct Client {
    sectors: Arc<RwLock<HashMap<PublicKey, HashMap<Hash256, Bytes>>>>,
    slow_hosts: Arc<RwLock<HashSet<PublicKey>>>,
    slow_delay: Arc<RwLock<Duration>>,
    /// Per-sector read delay. After each read, the delay is halved. Used to
    /// simulate out-of-order chunk completion.
    read_delays: Arc<RwLock<HashMap<Hash256, Duration>>>,
    initial_read_delay: Arc<RwLock<Option<Duration>>>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Self {
            sectors: Arc::new(RwLock::new(HashMap::new())),
            slow_hosts: Arc::new(RwLock::new(HashSet::new())),
            slow_delay: Arc::new(RwLock::new(Duration::ZERO)),
            read_delays: Arc::new(RwLock::new(HashMap::new())),
            initial_read_delay: Arc::new(RwLock::new(None)),
        }
    }

    /// Sets an initial per-sector read delay. After each read, the per-sector
    /// delay is halved. Used to simulate out-of-order chunk completion.
    /// Sectors written after this is set will start with `delay`.
    pub fn set_initial_read_delay(&self, delay: Duration) {
        *self.initial_read_delay.write().unwrap() = Some(delay);
    }

    pub fn clear(&self) {
        self.sectors.write().unwrap().clear();
    }

    /// Sets the given hosts as "slow" - they will sleep for the specified duration
    /// before completing any write_sector or read_sector operation.
    pub fn set_slow_hosts(&self, hosts: impl IntoIterator<Item = PublicKey>, delay: Duration) {
        let mut slow = self.slow_hosts.write().unwrap();
        slow.clear();
        slow.extend(hosts);
        *self.slow_delay.write().unwrap() = delay;
    }

    /// Clears all slow host settings.
    pub fn reset_slow_hosts(&self) {
        self.slow_hosts.write().unwrap().clear();
        *self.slow_delay.write().unwrap() = Duration::ZERO;
    }
}

impl Transport for Client {
    async fn host_prices(&self, _: &HostEndpoint) -> Result<HostPrices, RHP4Error> {
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
    ) -> Result<Hash256, RHP4Error> {
        if host.addresses.is_empty() {
            return Err(RHP4Error::Transport("host has no addresses".to_string()));
        }
        // Check if this host is configured as slow
        let slow_delay = {
            let slow_hosts = self.slow_hosts.read().unwrap();
            if slow_hosts.contains(&host.public_key) {
                Some(*self.slow_delay.read().unwrap())
            } else {
                None
            }
        };
        if let Some(delay) = slow_delay {
            sleep(delay).await;
        }

        sleep(Duration::from_millis(3)).await; // simulate network latency ~ 10Gbps
        let sector_root = sia_core::rhp4::sector_root(&sector);
        let mut sectors = self.sectors.write().unwrap();
        let host_sectors = sectors.entry(host.public_key).or_default();
        host_sectors.insert(sector_root, sector);
        if let Some(delay) = *self.initial_read_delay.read().unwrap() {
            self.read_delays.write().unwrap().insert(sector_root, delay);
        }
        Ok(sector_root)
    }

    async fn read_sector(
        &self,
        host: &HostEndpoint,
        _: HostPrices,
        _: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, RHP4Error> {
        if host.addresses.is_empty() {
            return Err(RHP4Error::Transport("host has no addresses".to_string()));
        }
        // Check if this host is configured as slow
        let slow_delay = {
            let slow_hosts = self.slow_hosts.read().unwrap();
            if slow_hosts.contains(&host.public_key) {
                Some(*self.slow_delay.read().unwrap())
            } else {
                None
            }
        };
        if let Some(delay) = slow_delay {
            sleep(delay).await;
        }

        // per-sector decreasing delay (used to simulate out-of-order chunk completion)
        let read_delay = {
            let mut delays = self.read_delays.write().unwrap();
            delays.get(&root).copied().map(|delay| {
                delays.insert(root, delay / 2);
                delay
            })
        };
        if let Some(delay) = read_delay {
            sleep(delay).await;
        }

        let sector = {
            let sectors = self.sectors.read().unwrap();
            let host_sectors = sectors
                .get(&host.public_key)
                .ok_or_else(|| RHP4Error::Transport("host not found".to_string()))?;
            let sector = host_sectors
                .get(&root)
                .ok_or_else(|| RHP4Error::Transport("sector not found".to_string()))?;
            Bytes::copy_from_slice(&sector[offset..offset + length])
        };
        sleep(Duration::from_nanos(sector.len() as u64 * 8 / 10)).await; // simulate network latency ~ 10Gbps
        Ok(sector)
    }
}
