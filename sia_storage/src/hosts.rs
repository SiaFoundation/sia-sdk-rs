use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use chrono::Utc;
use log::debug;
use serde::{Deserialize, Serialize};
use sia_core::rhp4::{HostPrices, SECTOR_SIZE};
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;
use sia_core::types::v2::NetAddress;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::hosts::metrics::{HostMetric, HostScore, RPCAverage, Transfer};
use crate::rhp4::{HostEndpoint, Transport};
use crate::time::{Duration, Elapsed, Instant, timeout};

mod metrics;

/// Represents a host in the Sia network. The
/// addresses can be used to connect to the host.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// A storage host on the Sia network.
pub struct Host {
    /// The host's public key.
    pub public_key: PublicKey,
    /// The host's network addresses.
    pub addresses: Vec<NetAddress>,
    /// The host's ISO 3166-1 alpha-2 country code.
    pub country_code: String,
    /// The host's latitude coordinate.
    pub latitude: f64,
    /// The host's longitude coordinate.
    pub longitude: f64,
    /// Whether the host is currently suitable for uploading data.
    pub good_for_upload: bool,
}

#[derive(Debug)]
struct HostInfo {
    addresses: Vec<NetAddress>,
    good_for_upload: bool,
    /// Number of upload RPCs currently in flight to this host. The guard
    /// is created by [`HostQueue::pick`] (incrementing this counter as
    /// part of the selection path) and dropped when the spawned upload
    /// task exits. Read by the scorer inside [`HostQueue::pick`].
    inflight_uploads: Arc<AtomicUsize>,
    /// Number of download RPCs currently in flight to this host. Updated
    /// by an [`InflightGuard`] in `Hosts::read_sector`; read by
    /// `prioritize` so concurrent slab downloads disperse across hosts
    /// instead of all piling onto the same top-N.
    inflight_downloads: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct HostList {
    hosts: RwLock<HashMap<PublicKey, HostInfo>>,
    metrics: RwLock<HashMap<PublicKey, HostMetric>>,
}

impl HostList {
    fn new() -> Self {
        Self {
            metrics: RwLock::new(HashMap::new()),
            hosts: RwLock::new(HashMap::new()),
        }
    }

    fn addresses(&self, host_key: &PublicKey) -> Option<Vec<NetAddress>> {
        let hosts = self.hosts.read().unwrap();
        hosts.get(host_key).map(|h| h.addresses.clone())
    }

    /// Sorts a list of items by their host's download score (descending).
    /// Score is `throughput / (inflight_downloads + 1)`, lower failure_rate
    /// wins first, and unsampled hosts get discovery priority. Used by the
    /// download path so concurrent slab downloads spread initial picks
    /// across less-busy hosts.
    fn prioritize<H, F>(&self, items: &mut [H], f: F)
    where
        F: Fn(&H) -> &PublicKey,
    {
        let metrics = self.metrics.read().unwrap();
        let host_info = self.hosts.read().unwrap();
        let score_for = |k: &PublicKey| -> Option<HostScore> {
            let metric = metrics.get(k)?;
            let inflight = host_info
                .get(k)
                .map(|h| h.inflight_downloads.load(Ordering::Relaxed))
                .unwrap_or(0);
            Some(HostScore::new(metric, inflight))
        };
        // Use `sort_by_cached_key` so each item's score is computed exactly
        // once. The inflight counter is an atomic that other tasks mutate
        // concurrently — recomputing during the sort would let the same
        // host's score change between comparisons, violating total order
        // and crashing the sort.
        items.sort_by_cached_key(|b| std::cmp::Reverse(score_for(f(b))));
    }

    /// Adds new hosts to the list if they don't already exist.
    ///
    /// If `clear` is true, existing hosts not in the new list are removed, but
    /// their metrics and inflight counters are retained in case they reappear later.
    fn update(&self, new_hosts: Vec<Host>, clear: bool) {
        let mut hosts = self.hosts.write().unwrap();
        // Preserve inflight counters across `clear=true` updates so guards
        // currently outstanding still decrement the right counter.
        let old = if clear {
            std::mem::take(&mut *hosts)
        } else {
            HashMap::new()
        };
        let mut metrics = self.metrics.write().unwrap();
        for host in new_hosts {
            let existing = hosts
                .get(&host.public_key)
                .or_else(|| old.get(&host.public_key));
            let inflight_uploads = existing
                .map(|h| h.inflight_uploads.clone())
                .unwrap_or_else(|| Arc::new(AtomicUsize::new(0)));
            let inflight_downloads = existing
                .map(|h| h.inflight_downloads.clone())
                .unwrap_or_else(|| Arc::new(AtomicUsize::new(0)));
            hosts.insert(
                host.public_key,
                HostInfo {
                    addresses: host.addresses,
                    good_for_upload: host.good_for_upload,
                    inflight_uploads,
                    inflight_downloads,
                },
            );
            metrics.entry(host.public_key).or_default();
        }
    }

    /// Returns the number of known hosts that are good for upload.
    fn available_for_upload(&self) -> usize {
        self.hosts
            .read()
            .unwrap()
            .iter()
            .filter(|(_, h)| h.good_for_upload)
            .count()
    }

    /// Snapshots the currently upload-eligible host keys. Used by
    /// [`HostQueue::new`] to seed the per-slab pool.
    fn upload_eligible_hosts(&self) -> Vec<PublicKey> {
        self.hosts
            .read()
            .unwrap()
            .iter()
            .filter_map(|(k, info)| info.good_for_upload.then_some(*k))
            .collect()
    }

    /// Begins tracking an in-flight download from the host. Returns a guard
    /// that increments the host's `inflight_downloads` counter immediately
    /// and decrements it on drop. Returns `None` if the host is unknown.
    fn track_inflight_download(&self, host_key: &PublicKey) -> Option<InflightGuard> {
        let counter = self
            .hosts
            .read()
            .unwrap()
            .get(host_key)?
            .inflight_downloads
            .clone();
        Some(InflightGuard::new(counter))
    }

    /// Mutates the per-host metric in place. Used by the sample/failure
    /// recording helpers below.
    fn with_metric<F>(&self, host_key: &PublicKey, f: F)
    where
        F: FnOnce(&mut HostMetric),
    {
        if let Some(metric) = self.metrics.write().unwrap().get_mut(host_key) {
            f(metric);
        }
    }

    /// Adds a failure for the given host, updating its metrics.
    fn add_failure(&self, host_key: PublicKey) {
        self.with_metric(&host_key, |m| m.add_failure());
    }

    /// Expected duration of a `size`-byte write to the host from its best
    /// recent pace. `None` until the host has a few write samples.
    fn estimate_write_duration(&self, host_key: &PublicKey, size: u32) -> Option<Duration> {
        let metrics = self.metrics.read().unwrap();
        Some(
            metrics
                .get(host_key)?
                .write_best_pace()?
                .estimate_duration(size),
        )
    }

    /// Expected duration of a `size`-byte read from the host from its best
    /// recent pace. `None` until the host has a few read samples.
    fn estimate_read_duration(&self, host_key: &PublicKey, size: u32) -> Option<Duration> {
        let metrics = self.metrics.read().unwrap();
        Some(
            metrics
                .get(host_key)?
                .read_best_pace()?
                .estimate_duration(size),
        )
    }

    /// Adds a read sample for the given host, updating its metrics.
    fn add_read_sample(&self, host_key: PublicKey, transfer: Transfer) {
        self.with_metric(&host_key, |m| m.add_read_sample(transfer));
    }

    /// Adds a write sample for the given host, updating its metrics.
    fn add_write_sample(&self, host_key: PublicKey, transfer: Transfer) {
        self.with_metric(&host_key, |m| m.add_write_sample(transfer));
    }
}

/// RAII guard that increments an `AtomicUsize` on construction and
/// decrements it on drop. Used to track per-host inflight uploads so the
/// host scorer reflects current load and is balanced even on early returns
/// or async cancellations.
pub(crate) struct InflightGuard(Arc<AtomicUsize>);

impl InflightGuard {
    /// Increments `counter` and returns a guard that decrements it on
    /// drop. The increment is part of the selection path so concurrent
    /// pickers see the load on their next scan rather than only after
    /// the RPC starts.
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct HostCache<T> {
    items: RwLock<HashMap<PublicKey, T>>,
}

impl<T> HostCache<T> {
    fn new() -> Self {
        Self {
            items: RwLock::new(HashMap::new()),
        }
    }

    fn get(&self, host_key: &PublicKey) -> Option<T>
    where
        T: Clone,
    {
        let cache = self.items.read().unwrap();
        cache.get(host_key).cloned()
    }

    fn set(&self, host_key: PublicKey, item: T) {
        let mut cache = self.items.write().unwrap();
        cache.insert(host_key, item);
    }
}

/// Errors that can occur during host RPCs.
#[derive(Debug, Error)]
pub enum RPCError {
    /// The host is not known to the SDK.
    #[error("unknown host: {0}")]
    UnknownHost(PublicKey),

    /// An error in the RHP4 protocol.
    #[error("RHP error: {0}")]
    Rhp(#[from] crate::rhp4::Error),

    /// The RPC timed out.
    #[error("RPC time out after {0:?}")]
    Elapsed(#[from] Elapsed),
}

/// Manages a list of known hosts and their performance metrics.
///
/// It allows updating the list of hosts, recording performance samples,
/// and prioritizing hosts based on their metrics.
///
/// It can be safely shared across threads and cloned.
///
/// This is public for criterion benchmarks, but not intended for general use
#[derive(Clone)]
pub(crate) struct Hosts<T: Transport> {
    transport: T,
    price_cache: Arc<HostCache<HostPrices>>,
    hosts: Arc<HostList>,

    global_write_avg: Arc<RwLock<RPCAverage>>,
    global_read_avg: Arc<RwLock<RPCAverage>>,
}

impl<T: Transport> Hosts<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            hosts: Arc::new(HostList::new()),
            price_cache: Arc::new(HostCache::new()),

            global_write_avg: Arc::new(RwLock::new(RPCAverage::default())),
            global_read_avg: Arc::new(RwLock::new(RPCAverage::default())),
        }
    }

    fn host_endpoint(&self, host_key: PublicKey) -> Result<HostEndpoint, RPCError> {
        let addresses = self.hosts.addresses(&host_key);
        match addresses {
            Some(addresses) => Ok(HostEndpoint {
                public_key: host_key,
                addresses,
            }),
            None => Err(RPCError::UnknownHost(host_key)),
        }
    }

    /// Sorts a list of hosts according to their priority in the client's
    /// preferred hosts queue. The function `f` is used to extract the
    /// public key from each item.
    pub fn prioritize<H, F>(&self, hosts: &mut [H], f: F)
    where
        F: Fn(&H) -> &PublicKey,
    {
        self.hosts.prioritize(hosts, f)
    }

    /// Adds new hosts to the list if they don't already exist
    ///
    /// If `clear` is true, existing hosts not in the new list are removed, but their metrics are retained.
    pub fn update(&self, new_hosts: Vec<Host>, clear: bool) {
        self.hosts.update(new_hosts, clear);
    }

    /// Returns the number of known hosts that are good for upload.
    pub fn available_for_upload(&self) -> usize {
        self.hosts.available_for_upload()
    }

    /// Creates a per-slab [`HostQueue`] seeded with the currently
    /// upload-eligible hosts. The queue enforces slab uniqueness (each
    /// host can be picked at most once until retried) and caps re-picks
    /// per host via [`MAX_RETRIES`]. Each upload slab should construct
    /// its own.
    pub fn upload_queue(&self) -> HostQueue {
        HostQueue::new(self.hosts.clone(), self.hosts.upload_eligible_hosts())
    }

    /// Reserves an inflight slot for a download from the given host. The
    /// returned guard increments `inflight_downloads` immediately so
    /// concurrent `prioritize` calls see the load, and decrements on drop.
    /// Callers should create the guard before spawning the download task
    /// and hold it for the duration of the RPC.
    pub fn reserve_inflight_download(&self, host_key: &PublicKey) -> Option<InflightGuard> {
        self.hosts.track_inflight_download(host_key)
    }

    /// Adds a failure for the given host, updating its metrics and priority.
    pub fn add_failure(&self, host_key: PublicKey) {
        self.hosts.add_failure(host_key);
    }

    /// Expected duration of a `size`-byte write to the host from its own
    /// throughput EMA.
    pub fn estimate_write_duration(&self, host_key: &PublicKey, size: u32) -> Option<Duration> {
        self.hosts.estimate_write_duration(host_key, size)
    }

    /// Expected duration of a `size`-byte read to the host from its own
    /// throughput EMA.
    pub fn estimate_read_duration(&self, host_key: &PublicKey, size: u32) -> Option<Duration> {
        self.hosts.estimate_read_duration(host_key, size)
    }

    /// Records a successful write for the host's metrics and the global
    /// write throughput EMA. Zero-size or zero-duration transfers are
    /// skipped rather than recorded as infinite throughput.
    pub fn record_write_sample(&self, host_key: PublicKey, size: u32, elapsed: Duration) {
        let Some(transfer) = Transfer::try_new(size, elapsed) else {
            return;
        };
        self.hosts.add_write_sample(host_key, transfer);
        self.global_write_avg
            .write()
            .unwrap()
            .add_sample(transfer.rate());
    }

    /// Read equivalent of [`Self::record_write_sample`].
    pub fn record_read_sample(&self, host_key: PublicKey, size: u32, elapsed: Duration) {
        let Some(transfer) = Transfer::try_new(size, elapsed) else {
            return;
        };
        self.hosts.add_read_sample(host_key, transfer);
        self.global_read_avg
            .write()
            .unwrap()
            .add_sample(transfer.rate());
    }

    /// Expected duration of a `bytes`-sized write on a typical host.
    /// Falls back to a static until the first write is sampled.
    pub fn write_estimate(&self, bytes: u32) -> Duration {
        const DEFAULT: Transfer = Transfer::new(SECTOR_SIZE as u32, Duration::from_secs(5));
        self.global_write_avg
            .read()
            .unwrap()
            .avg()
            .map(|rate| Duration::from_secs_f64(bytes as f64 / *rate))
            .unwrap_or_else(|| DEFAULT.estimate_duration(bytes))
    }

    /// Expected duration of a `bytes`-sized read on a typical host.
    /// Falls back to a static until the first read is sampled.
    pub fn read_estimate(&self, bytes: u32) -> Duration {
        const DEFAULT: Transfer = Transfer::new(1 << 20, Duration::from_secs(1));
        self.global_read_avg
            .read()
            .unwrap()
            .avg()
            .map(|rate| Duration::from_secs_f64(bytes as f64 / *rate))
            .unwrap_or_else(|| DEFAULT.estimate_duration(bytes))
    }

    /// Warms connections to the given hosts by prefetching their prices. This can help seed
    /// the RPC performance metrics for new hosts before they're used for actual uploads
    /// or downloads.
    pub async fn warm_connections(&self, hosts: Vec<HostEndpoint>) {
        let hosts_len = hosts.len();
        let mut warmed_conns: usize = 0;
        let mut inflight_scans = JoinSet::new();
        let sema = Arc::new(Semaphore::new(15));
        for host in hosts {
            let transport = self.transport.clone();
            let price_cache = self.price_cache.clone();
            let hosts = self.hosts.clone();

            let sema = sema.clone();
            join_set_spawn!(inflight_scans, async move {
                let _permit = sema.acquire().await.unwrap();
                let start = Instant::now();

                match Self::fetch_prices(
                    transport,
                    &price_cache,
                    &hosts,
                    &host,
                    Duration::from_secs(1),
                    false,
                )
                .await
                {
                    Ok((_, pulled)) if pulled => {
                        debug!(
                            "warmed connection to host {} in {:?}",
                            host.public_key,
                            start.elapsed()
                        );
                        true
                    }
                    _ => false,
                }
            });
        }

        while let Some(res) = inflight_scans.join_next().await {
            if let Ok(warmed) = res
                && warmed
            {
                warmed_conns += 1;
            }
        }
        debug!("warmed {warmed_conns}/{hosts_len} connections");
    }

    async fn fetch_prices(
        transport: T,
        cache: &HostCache<HostPrices>,
        hosts: &HostList,
        host_endpoint: &HostEndpoint,
        fetch_timeout: Duration,
        refresh: bool,
    ) -> Result<(HostPrices, bool), RPCError> {
        if !refresh
            && let Some(prices) = cache.get(&host_endpoint.public_key)
            && prices.valid_until > Utc::now()
        {
            Ok((prices, false))
        } else {
            let (prices, _) = timeout(fetch_timeout, transport.host_prices(host_endpoint))
                .await
                .inspect_err(|_| hosts.add_failure(host_endpoint.public_key))?
                .inspect_err(|_| hosts.add_failure(host_endpoint.public_key))?;
            cache.set(host_endpoint.public_key, prices.clone());
            Ok((prices, true))
        }
    }

    /// Performs an upload RPC to the given host. The caller is responsible
    /// for holding the [`InflightGuard`] returned by [`HostQueue::pick`]
    /// for the duration of this call so the host scorer reflects the load.
    pub async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: bytes::Bytes,
        write_timeout: Duration,
    ) -> Result<Hash256, RPCError> {
        let host = self.host_endpoint(host_key)?;
        timeout(write_timeout, async {
            let (prices, _) = Self::fetch_prices(
                self.transport.clone(),
                &self.price_cache,
                &self.hosts,
                &host,
                write_timeout,
                false,
            )
            .await?;
            let bytes = sector.len() as u32;
            let (root, elapsed) = self
                .transport
                .write_sector(&host, prices, account_key, sector)
                .await
                .inspect_err(|_| self.hosts.add_failure(host_key))
                .map_err(RPCError::Rhp)?;
            self.record_write_sample(host_key, bytes, elapsed);
            Ok(root)
        })
        .await?
    }

    /// Performs a download RPC from the given host. The caller is
    /// responsible for holding the [`InflightGuard`] returned by
    /// [`Self::reserve_inflight_download`] for the duration of this call so
    /// the host scorer reflects the load.
    pub async fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
        read_timeout: Duration,
    ) -> Result<bytes::Bytes, RPCError> {
        let host = self.host_endpoint(host_key)?;
        let bytes = length as u32;
        timeout(read_timeout, async {
            let (prices, _) = Self::fetch_prices(
                self.transport.clone(),
                &self.price_cache,
                &self.hosts,
                &host,
                read_timeout,
                false,
            )
            .await?;
            let (data, elapsed) = self
                .transport
                .read_sector(&host, prices, account_key, root, offset, length)
                .await
                .inspect_err(|_| self.hosts.add_failure(host_key))
                .map_err(RPCError::Rhp)?;
            self.record_read_sample(host_key, bytes, elapsed);
            Ok(data)
        })
        .await?
    }
}

/// Errors from the host selection queue.
#[derive(Debug, Error)]
pub enum QueueError {
    /// All available hosts have been tried and failed.
    #[error("no more hosts available")]
    NoMoreHosts,
    /// Not enough hosts are available to meet the required shard count.
    #[error("not enough initial hosts")]
    InsufficientHosts,
    /// The host queue has been closed.
    #[error("client closed")]
    Closed,
    /// An internal mutex was poisoned.
    #[error("internal mutex error")]
    MutexError,
    /// The host has been retried too many times.
    #[error("host retry limit exceeded")]
    MaxRetriesExceeded,
}

/// Maximum number of attempts per host within a single slab — initial
/// pick plus retries. A host with a transient failure should get a few
/// more chances within the slab rather than being permanently sidelined
/// on the first error.
const MAX_RETRIES: usize = 3;

/// Per-slab pool of upload hosts. Snapshots upload-eligible hosts at
/// construction and hands them out one at a time. Failed hosts can be
/// returned via [`HostQueue::retry`] for re-pick, capped at
/// [`MAX_RETRIES`] attempts per host across the slab.
///
/// `available` is a snapshot, not a live view of [`HostList`]: hosts
/// removed via [`Hosts::update`] after construction stay in the pool but
/// are filtered at pick time when they no longer exist in `HostList`.
/// Slabs live for seconds, so snapshot staleness doesn't materially
/// affect placement.
pub(crate) struct HostQueue {
    hosts: Arc<HostList>,
    available: Vec<PublicKey>,
    attempts: HashMap<PublicKey, usize>,
}

impl HostQueue {
    fn new(hosts: Arc<HostList>, available: Vec<PublicKey>) -> Self {
        Self {
            hosts,
            available,
            attempts: HashMap::new(),
        }
    }

    /// Picks the best host from the pool and atomically reserves an
    /// inflight slot. Scoring matches [`HostScore`]: lower `failure_rate`
    /// wins, then unsampled hosts outrank sampled (discovery), then
    /// `throughput / (inflight + 1)` among sampled. The winner is removed
    /// from `available`; the returned [`InflightGuard`] must be held for
    /// the duration of the upload RPC so concurrent pickers see the load.
    pub(crate) fn pick(&mut self) -> Option<(PublicKey, InflightGuard)> {
        let host_info = self.hosts.hosts.read().unwrap();
        let metrics = self.hosts.metrics.read().unwrap();
        let mut best: Option<(usize, HostScore, Arc<AtomicUsize>)> = None;
        for (i, hk) in self.available.iter().enumerate() {
            let Some(info) = host_info.get(hk) else {
                continue;
            };
            let Some(metric) = metrics.get(hk) else {
                continue;
            };
            let inflight = info.inflight_uploads.load(Ordering::Relaxed);
            let score = HostScore::new(metric, inflight);
            match &best {
                None => best = Some((i, score, info.inflight_uploads.clone())),
                Some((_, current, _)) if score > *current => {
                    best = Some((i, score, info.inflight_uploads.clone()))
                }
                _ => {}
            }
        }
        let (i, _, counter) = best?;
        drop(host_info);
        drop(metrics);
        let host = self.available.swap_remove(i);
        Some((host, InflightGuard::new(counter)))
    }

    /// Returns a failed host to the pool so it can be re-picked. Returns
    /// `true` when the host went back into `available`, `false` when its
    /// per-slab attempt budget is exhausted.
    pub(crate) fn retry(&mut self, host: PublicKey) -> bool {
        let attempts = self.attempts.entry(host).or_default();
        *attempts += 1;
        if *attempts >= MAX_RETRIES {
            return false;
        }
        self.available.push(host);
        true
    }
}

#[cfg(test)]
mod test {
    use crate::rhp4::Client;
    use sia_core::signing::PrivateKey;

    use super::*;

    fn random_pubkey() -> sia_core::signing::PublicKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        PrivateKey::from_seed(&seed).public_key()
    }

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[sia_core_derive::cross_target_test]
    fn test_host_queue_pick() {
        let hosts_manager = Hosts::new(Client::new());
        let hk1 = random_pubkey();
        let hk2 = random_pubkey();
        let hk3 = random_pubkey();
        hosts_manager.update(
            vec![
                Host {
                    public_key: hk1,
                    addresses: vec![],
                    country_code: String::new(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                },
                Host {
                    public_key: hk2,
                    addresses: vec![],
                    country_code: String::new(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: false, // not upload-eligible
                },
                Host {
                    public_key: hk3,
                    addresses: vec![],
                    country_code: String::new(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                },
            ],
            true,
        );

        // With no samples and no inflight, both hk1 and hk3 are eligible
        // and have equal score; result is deterministic-enough — we just
        // assert it returns one of them, and that hk2 (not good_for_upload)
        // is never in the pool.
        let mut queue = hosts_manager.upload_queue();
        let (first, first_guard) = queue.pick().unwrap();
        assert!(first == hk1 || first == hk3);
        assert_ne!(first, hk2);

        // Second pick consumes the other eligible host.
        let (second, second_guard) = queue.pick().unwrap();
        assert!(second == hk1 || second == hk3);
        assert_ne!(second, first);
        assert_ne!(second, hk2);

        // Pool empty — no more picks available.
        assert!(queue.pick().is_none());

        // Drop the guards explicitly so the counters balance.
        drop(first_guard);
        drop(second_guard);
    }

    #[sia_core_derive::cross_target_test]
    fn test_host_queue_retry_cap() {
        // `retry` lets a host be re-picked, but MAX_RETRIES caps the total
        // attempts per host across the slab.
        let hosts_manager = Hosts::new(Client::new());
        let hk = random_pubkey();
        hosts_manager.update(
            vec![Host {
                public_key: hk,
                addresses: vec![],
                country_code: String::new(),
                latitude: 0.0,
                longitude: 0.0,
                good_for_upload: true,
            }],
            true,
        );

        let mut queue = hosts_manager.upload_queue();
        for i in 0..MAX_RETRIES {
            let (picked, guard) = queue.pick().unwrap();
            assert_eq!(picked, hk);
            drop(guard);
            let pushed = queue.retry(picked);
            let expected = i < MAX_RETRIES - 1;
            assert_eq!(pushed, expected, "retry #{i} returned wrong value");
        }
        assert!(queue.pick().is_none(), "should respect retry cap");
    }

    #[sia_core_derive::cross_target_test]
    fn test_host_score_orders_by_weighted_throughput() {
        // Same metric but different inflight: the less-loaded host wins.
        let metric = {
            let mut m = HostMetric::default();
            m.add_write_sample(Transfer::new(1_000_000, Duration::from_secs(1)));
            m
        };
        let busy = HostScore::new(&metric, 4);
        let idle = HostScore::new(&metric, 0);
        assert!(idle > busy, "less-loaded host should outrank busy host");

        // A 10x faster host beats an idle slow host even when it has some load.
        let fast_metric = {
            let mut m = HostMetric::default();
            m.add_write_sample(Transfer::new(10_000_000, Duration::from_secs(1)));
            m
        };
        let fast_busy = HostScore::new(&fast_metric, 4);
        let slow_idle = HostScore::new(&metric, 0);
        assert!(
            fast_busy > slow_idle,
            "fast-but-busy should beat slow-and-idle when fast is >Nx faster",
        );

        // Failure rate trumps throughput.
        let failing = {
            let mut m = fast_metric.clone();
            for _ in 0..5 {
                m.add_failure();
            }
            m
        };
        let failing_score = HostScore::new(&failing, 0);
        let healthy_score = HostScore::new(&metric, 0);
        assert!(
            healthy_score > failing_score,
            "healthy host should outrank a failing fast host",
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_prioritize_uses_download_inflight() {
        // Two hosts with identical throughput samples; bumping one host's
        // download inflight counter should push it down in the sorted
        // order. Mirrors the upload-side `next_upload_host` behavior so
        // concurrent slab downloads spread across less-busy hosts.
        let hosts_manager = Hosts::new(Client::new());
        let hk1 = random_pubkey();
        let hk2 = random_pubkey();
        hosts_manager.update(
            vec![
                Host {
                    public_key: hk1,
                    addresses: vec![],
                    country_code: String::new(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                },
                Host {
                    public_key: hk2,
                    addresses: vec![],
                    country_code: String::new(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                },
            ],
            true,
        );
        // Sample both with the same throughput so the inflight counter is
        // the only differentiator.
        hosts_manager
            .hosts
            .add_read_sample(hk1, Transfer::new(1_000_000, Duration::from_secs(1)));
        hosts_manager
            .hosts
            .add_read_sample(hk2, Transfer::new(1_000_000, Duration::from_secs(1)));

        // With both idle, sort order is arbitrary among ties — assert the
        // ranking switches when we add inflight to one of them.
        let mut items = vec![hk1, hk2];
        hosts_manager.hosts.prioritize(&mut items, |k| k);
        let initial_first = items[0];
        let initial_second = items[1];

        // Bump inflight on whichever host happened to be first by holding
        // three live guards on it.
        let _guards: Vec<_> = (0..3)
            .map(|_| {
                hosts_manager
                    .hosts
                    .track_inflight_download(&initial_first)
                    .unwrap()
            })
            .collect();

        let mut items = vec![hk1, hk2];
        hosts_manager.hosts.prioritize(&mut items, |k| k);
        assert_eq!(
            items[0], initial_second,
            "host with higher download inflight should sort second",
        );
        assert_eq!(items[1], initial_first);
    }
}
