use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use chrono::Utc;
use sia_core::encoding;
use sia_core::rhp4::protocol::Error as ProtocolError;
use sia_core::rhp4::{AccountToken, HostPrices};
use sia_core::signing::{PrivateKey, PublicKey, Signature};
use sia_core::types::{Currency, Hash256};

use super::{Error as RHP4Error, HostEndpoint, Transport};
use crate::sector_stream::SectorBody;
use crate::time::{Duration, Instant, sleep};

#[derive(Clone)]
pub struct Client {
    sectors: Arc<RwLock<HashMap<PublicKey, HashMap<Hash256, Bytes>>>>,
    slow_hosts: Arc<RwLock<HashSet<PublicKey>>>,
    slow_delay: Arc<RwLock<Duration>>,
    /// Per-sector read delay. After each read, the delay is halved. Used to
    /// simulate out-of-order chunk completion.
    read_delays: Arc<RwLock<HashMap<Hash256, Duration>>>,
    initial_read_delay: Arc<RwLock<Option<Duration>>>,
    read_failures: Arc<RwLock<HashMap<PublicKey, usize>>>,
    price_delay: Arc<RwLock<Duration>>,
    price_requests: Arc<AtomicUsize>,
    price_failures: Arc<AtomicUsize>,
    read_requests: Arc<AtomicUsize>,
    /// Key sectors by a fast hash instead of their Merkle root.
    fast_roots: Arc<AtomicBool>,
    /// When the first write began, received its first byte, and finished,
    /// since the last reset. For benchmarks.
    write_timeline: Arc<RwLock<WriteTimeline>>,
}

/// Instants of the first sector write since the last reset.
#[derive(Clone, Copy, Default, Debug)]
pub struct WriteTimeline {
    pub first_call: Option<Instant>,
    pub first_byte: Option<Instant>,
    pub first_done: Option<Instant>,
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
            read_failures: Arc::new(RwLock::new(HashMap::new())),
            price_delay: Arc::new(RwLock::new(Duration::ZERO)),
            price_requests: Arc::new(AtomicUsize::new(0)),
            price_failures: Arc::new(AtomicUsize::new(0)),
            read_requests: Arc::new(AtomicUsize::new(0)),
            fast_roots: Arc::new(AtomicBool::new(false)),
            write_timeline: Arc::new(RwLock::new(WriteTimeline::default())),
        }
    }

    /// Keys written sectors by an xxh3 hash of their contents instead of
    /// their Merkle root, which costs 10 ms per sector in wasm. The client
    /// treats the root as opaque, so only benchmarks notice; roots written
    /// this way are not real sector roots.
    pub fn set_fast_roots(&self, enabled: bool) {
        self.fast_roots.store(enabled, Ordering::Relaxed);
    }

    pub fn reset_write_timeline(&self) {
        *self.write_timeline.write().unwrap() = WriteTimeline::default();
    }

    pub fn write_timeline(&self) -> WriteTimeline {
        *self.write_timeline.read().unwrap()
    }

    fn sector_key(&self, sector: &[u8]) -> Hash256 {
        if !self.fast_roots.load(Ordering::Relaxed) {
            return sia_core::rhp4::sector_root(sector);
        }
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&xxhash_rust::xxh3::xxh3_128_with_seed(sector, 0).to_le_bytes());
        key[16..].copy_from_slice(&xxhash_rust::xxh3::xxh3_128_with_seed(sector, 1).to_le_bytes());
        Hash256::from(key)
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

    /// Sleeps out the host's configured slow delay. A delay longer than
    /// `idle_timeout` is a stall, which the real transports report once
    /// the idle limit passes. The error takes the shape a stalled response
    /// has after passing through the protocol decoder.
    async fn stall(&self, host: &PublicKey, idle_timeout: Duration) -> Result<(), RHP4Error> {
        let delay = {
            let slow_hosts = self.slow_hosts.read().unwrap();
            if slow_hosts.contains(host) {
                Some(*self.slow_delay.read().unwrap())
            } else {
                None
            }
        };
        let Some(delay) = delay else {
            return Ok(());
        };
        if delay > idle_timeout {
            sleep(idle_timeout).await;
            let io = std::io::Error::new(std::io::ErrorKind::TimedOut, "stream idle");
            return Err(ProtocolError::from(encoding::Error::from(io)).into());
        }
        sleep(delay).await;
        Ok(())
    }
}

#[cfg(test)]
impl Client {
    /// Fails the next `count` `read_sector` calls to each of the given hosts,
    /// after which reads are served normally.
    pub fn set_read_failures(&self, hosts: impl IntoIterator<Item = PublicKey>, count: usize) {
        let mut failures = self.read_failures.write().unwrap();
        failures.clear();
        failures.extend(hosts.into_iter().map(|host| (host, count)));
    }

    /// Sets an initial per-sector read delay. After each read, the per-sector
    /// delay is halved. Used to simulate out-of-order chunk completion.
    /// Sectors written after this is set will start with `delay`.
    pub fn set_initial_read_delay(&self, delay: Duration) {
        *self.initial_read_delay.write().unwrap() = Some(delay);
    }

    /// Delays every `host_prices` call by `delay`.
    pub fn set_price_delay(&self, delay: Duration) {
        *self.price_delay.write().unwrap() = delay;
    }

    /// Number of `host_prices` calls served so far.
    pub fn price_requests(&self) -> usize {
        self.price_requests.load(Ordering::Relaxed)
    }

    /// Fails the next `count` `host_prices` calls, after which prices are
    /// served normally.
    pub fn set_price_failures(&self, count: usize) {
        self.price_failures.store(count, Ordering::Relaxed);
    }

    /// Number of `read_sector` calls started so far.
    pub fn read_requests(&self) -> usize {
        self.read_requests.load(Ordering::Relaxed)
    }
}

impl Transport for Client {
    async fn host_prices(
        &self,
        _: &HostEndpoint,
        _: Duration,
    ) -> Result<(HostPrices, Duration), RHP4Error> {
        let start = Instant::now();
        self.price_requests.fetch_add(1, Ordering::Relaxed);
        let delay = *self.price_delay.read().unwrap();
        if !delay.is_zero() {
            sleep(delay).await;
        }
        if self
            .price_failures
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(RHP4Error::Transport("price fetch failed".to_string()));
        }
        let prices = HostPrices {
            contract_price: Currency::zero(),
            collateral: Currency::zero(),
            ingress_price: Currency::zero(),
            egress_price: Currency::zero(),
            storage_price: Currency::zero(),
            free_sector_price: Currency::zero(),
            tip_height: 1,
            signature: Signature::default(),
            valid_until: Utc::now() + chrono::Duration::days(1),
        };
        Ok((prices, start.elapsed()))
    }

    async fn write_sector(
        &self,
        host: &HostEndpoint,
        _: HostPrices,
        _: &PrivateKey,
        sector: SectorBody,
        idle_timeout: Duration,
    ) -> Result<(Hash256, Duration), RHP4Error> {
        if host.addresses.is_empty() {
            return Err(RHP4Error::Transport("host has no addresses".to_string()));
        }
        let start = Instant::now();
        self.write_timeline
            .write()
            .unwrap()
            .first_call
            .get_or_insert(start);
        self.stall(&host.public_key, idle_timeout).await?;

        // Receive the body as the producer publishes it, like a host would.
        let mut data = bytes::BytesMut::with_capacity(sector.len());
        let mut sector = sector;
        while let Some(chunk) = sector.next_chunk().await {
            if data.is_empty() {
                self.write_timeline
                    .write()
                    .unwrap()
                    .first_byte
                    .get_or_insert(Instant::now());
            }
            data.extend_from_slice(&chunk);
        }
        let sector = data.freeze();
        sleep(Duration::from_millis(3)).await; // simulate network latency ~ 10Gbps
        let sector_root = self.sector_key(&sector);
        self.write_timeline
            .write()
            .unwrap()
            .first_done
            .get_or_insert(Instant::now());
        let mut sectors = self.sectors.write().unwrap();
        let host_sectors = sectors.entry(host.public_key).or_default();
        host_sectors.insert(sector_root, sector);
        if let Some(delay) = *self.initial_read_delay.read().unwrap() {
            self.read_delays.write().unwrap().insert(sector_root, delay);
        }
        Ok((sector_root, start.elapsed()))
    }

    async fn read_sector(
        &self,
        host: &HostEndpoint,
        _: HostPrices,
        _: AccountToken,
        root: Hash256,
        range: Range<usize>,
        idle_timeout: Duration,
    ) -> Result<(Bytes, Duration), RHP4Error> {
        self.read_requests.fetch_add(1, Ordering::Relaxed);
        if host.addresses.is_empty() {
            return Err(RHP4Error::Transport("host has no addresses".to_string()));
        }
        let start = Instant::now();
        self.stall(&host.public_key, idle_timeout).await?;

        let fail = {
            let mut failures = self.read_failures.write().unwrap();
            match failures.get_mut(&host.public_key) {
                Some(remaining) if *remaining > 0 => {
                    *remaining -= 1;
                    true
                }
                _ => false,
            }
        };
        if fail {
            return Err(RHP4Error::Transport("injected read failure".to_string()));
        }

        // per-sector decreasing delay (used to simulate out-of-order chunk completion)
        let read_delay = {
            let mut delays = self.read_delays.write().unwrap();
            delays.get(&root).copied().inspect(|&delay| {
                delays.insert(root, delay / 2);
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
            Bytes::copy_from_slice(&sector[range])
        };
        sleep(Duration::from_nanos(sector.len() as u64 * 8 / 10)).await; // simulate network latency ~ 10Gbps
        Ok((sector, start.elapsed()))
    }
}
