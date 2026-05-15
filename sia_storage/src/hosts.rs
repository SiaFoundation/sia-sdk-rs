use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use chrono::Utc;
use log::debug;
use serde::{Deserialize, Serialize};
use sia_core::rhp4::HostPrices;
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;
use sia_core::types::v2::NetAddress;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::rhp4::{HostEndpoint, Transport};
use crate::time::{Duration, Elapsed, Instant, timeout};

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

#[derive(Debug, Default, Clone)]
struct RPCAverage(Option<f64>); // exponential moving average of throughput in bytes/sec

impl RPCAverage {
    const ALPHA: f64 = 0.2;

    fn add_sample(&mut self, bytes_per_sec: u64) {
        match self.0 {
            Some(avg) => {
                self.0 = Some(Self::ALPHA * (bytes_per_sec as f64) + (1.0 - Self::ALPHA) * avg);
            }
            None => {
                self.0 = Some(bytes_per_sec as f64);
            }
        }
    }

    /// Returns the current average in bytes/sec, or `None` if no samples have
    /// been recorded yet. Callers decide how to treat unsampled hosts.
    fn avg(&self) -> Option<f64> {
        self.0
    }
}

impl Display for RPCAverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.avg() {
            Some(v) => Display::fmt(&v, f),
            None => f.write_str("unsampled"),
        }
    }
}

impl PartialEq for RPCAverage {
    fn eq(&self, other: &Self) -> bool {
        self.avg() == other.avg()
    }
}

impl Eq for RPCAverage {}

#[derive(Debug, Default, Clone)]
struct FailureRate(Option<f64>); // exponential moving average of failure rate

impl FailureRate {
    const ALPHA: f64 = 0.2;

    fn add_sample(&mut self, success: bool) {
        let sample = if success { 0.0 } else { 1.0 };
        match self.0 {
            Some(rate) => {
                self.0 = Some(Self::ALPHA * sample + (1.0 - Self::ALPHA) * rate);
            }
            None => {
                self.0 = Some(sample);
            }
        }
    }

    // Computes the failure rate as an integer percentage (0-100)
    fn rate(&self) -> i64 {
        match self.0 {
            Some(rate) => (rate * 100.0).round() as i64,
            None => 0, // presume no failures if no samples
        }
    }
}

impl Display for FailureRate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}%", self.rate())
    }
}

impl PartialEq for FailureRate {
    fn eq(&self, other: &Self) -> bool {
        self.rate() == other.rate()
    }
}

impl Eq for FailureRate {}

impl PartialOrd for FailureRate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FailureRate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rate().cmp(&other.rate())
    }
}

#[derive(Debug, Default, Clone)]
struct HostMetric {
    rpc_write_avg: RPCAverage,
    rpc_read_avg: RPCAverage,
    failure_rate: FailureRate,
}

impl HostMetric {
    fn add_write_sample(&mut self, bytes: u64, elapsed: Duration) {
        if let Some(bps) = bytes_per_sec(bytes, elapsed) {
            self.rpc_write_avg.add_sample(bps);
        }
        self.failure_rate.add_sample(true);
    }

    fn add_read_sample(&mut self, bytes: u64, elapsed: Duration) {
        if let Some(bps) = bytes_per_sec(bytes, elapsed) {
            self.rpc_read_avg.add_sample(bps);
        }
        self.failure_rate.add_sample(true);
    }

    fn add_settings_sample(&mut self, elapsed: Duration) {
        self.add_read_sample(270, elapsed); // serialized settings response is ~270 bytes
    }

    fn add_failure(&mut self) {
        self.failure_rate.add_sample(false);
    }

    /// Combined read + write throughput average. `None` only when neither side
    /// has been sampled. Used by [`HostScore`] for the discovery preference
    /// (unsampled outranks sampled).
    fn combined_throughput(&self) -> Option<f64> {
        match (self.rpc_write_avg.avg(), self.rpc_read_avg.avg()) {
            (None, None) => None,
            (Some(w), Some(r)) => Some((w + r) / 2.0),
            (Some(v), None) | (None, Some(v)) => Some(v),
        }
    }
}

// Computes throughput in bytes/sec, returning None when elapsed is zero so that
// the sample is skipped instead of producing an invalid/infinite throughput
// value that would skew the moving average.
fn bytes_per_sec(bytes: u64, elapsed: Duration) -> Option<u64> {
    if elapsed.is_zero() {
        return None;
    }
    Some((bytes as f64 / elapsed.as_secs_f64()) as u64)
}

/// Score for picking the next upload host. Higher is better.
///
/// Sort order:
/// 1. Lower `failure_rate` wins.
/// 2. Unsampled hosts (no throughput data) outrank sampled ones — this is
///    the "discovery" preference so every available host eventually gets
///    tried at least once.
/// 3. Among sampled hosts, higher `throughput / (inflight + 1)` wins —
///    the expected per-shard throughput if you added one more shard. That
///    penalizes already-busy hosts proportionally to load, so a saturated
///    fast host can lose to an idle slower one, while a genuinely much
///    faster host still wins even when serving a few shards.
#[derive(Debug, Clone, Copy)]
struct HostScore {
    failure_rate: i64,
    throughput: Option<f64>,
    inflight: usize,
}

impl HostScore {
    fn new(metric: &HostMetric, inflight: usize) -> Self {
        Self {
            failure_rate: metric.failure_rate.rate(),
            throughput: metric.combined_throughput(),
            inflight,
        }
    }

    fn weighted_throughput(&self) -> Option<f64> {
        self.throughput.map(|t| t / (self.inflight as f64 + 1.0))
    }
}

impl PartialEq for HostScore {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for HostScore {}

impl Ord for HostScore {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Lower failure_rate is better (so invert here for max-comparison).
        match other.failure_rate.cmp(&self.failure_rate) {
            std::cmp::Ordering::Equal => match (self.throughput, other.throughput) {
                (None, None) => std::cmp::Ordering::Equal,
                // discovery: unsampled outranks sampled
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(_), None) => std::cmp::Ordering::Less,
                (Some(_), Some(_)) => self
                    .weighted_throughput()
                    .unwrap()
                    .total_cmp(&other.weighted_throughput().unwrap()),
            },
            ord => ord,
        }
    }
}

impl PartialOrd for HostScore {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
struct HostInfo {
    addresses: Vec<NetAddress>,
    good_for_upload: bool,
    /// Number of upload RPCs currently in flight to this host. Updated by
    /// an [`InflightGuard`] in `Hosts::write_sector`; read by the host
    /// scorer in `next_upload_host`.
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

    /// Returns the upload host with the best score for handling another
    /// shard, excluding any in `exclude`. The score is
    /// `throughput / (inflight + 1)` and lower `failure_rate` wins first.
    /// Returns `None` if no eligible host is available.
    fn next_upload_host(&self, exclude: &HashSet<PublicKey>) -> Option<PublicKey> {
        let hosts = self.hosts.read().unwrap();
        let metrics = self.metrics.read().unwrap();
        let mut best: Option<(PublicKey, HostScore)> = None;
        for (hk, info) in hosts.iter() {
            if !info.good_for_upload || exclude.contains(hk) {
                continue;
            }
            let Some(metric) = metrics.get(hk) else {
                continue;
            };
            let inflight = info.inflight_uploads.load(Ordering::Relaxed);
            let score = HostScore::new(metric, inflight);
            match &best {
                None => best = Some((*hk, score)),
                Some((_, current)) if score > *current => best = Some((*hk, score)),
                _ => {}
            }
        }
        best.map(|(hk, _)| hk)
    }

    /// Begins tracking an in-flight upload to the host. Returns a guard that
    /// increments the host's `inflight_uploads` counter immediately and
    /// decrements it on drop. Returns `None` if the host is unknown.
    fn track_inflight_upload(&self, host_key: &PublicKey) -> Option<InflightGuard> {
        let counter = self
            .hosts
            .read()
            .unwrap()
            .get(host_key)?
            .inflight_uploads
            .clone();
        Some(InflightGuard::new(counter))
    }

    /// Download analogue of [`Self::track_inflight_upload`].
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

    /// Adds a read sample for the given host, updating its metrics.
    fn add_read_sample(&self, host_key: PublicKey, bytes: u64, elapsed: Duration) {
        self.with_metric(&host_key, |m| m.add_read_sample(bytes, elapsed));
    }

    /// Adds a write sample for the given host, updating its metrics.
    fn add_write_sample(&self, host_key: PublicKey, bytes: u64, elapsed: Duration) {
        self.with_metric(&host_key, |m| m.add_write_sample(bytes, elapsed));
    }

    fn add_settings_sample(&self, host_key: PublicKey, elapsed: Duration) {
        self.with_metric(&host_key, |m| m.add_settings_sample(elapsed));
    }
}

/// RAII guard that increments an `AtomicUsize` on construction and
/// decrements it on drop. Used to track per-host inflight uploads so the
/// host scorer reflects current load and is balanced even on early returns
/// or async cancellations.
struct InflightGuard(Arc<AtomicUsize>);

impl InflightGuard {
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
}

impl<T: Transport> Hosts<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            hosts: Arc::new(HostList::new()),
            price_cache: Arc::new(HostCache::new()),
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

    /// Picks the best host for the next shard upload, excluding any in
    /// `exclude`. The scorer favors the host with the highest
    /// `throughput / (inflight + 1)` — i.e. best expected per-shard
    /// throughput if you added one more shard. Returns `None` if no
    /// eligible host is available.
    pub fn next_upload_host(&self, exclude: &HashSet<PublicKey>) -> Option<PublicKey> {
        self.hosts.next_upload_host(exclude)
    }

    /// Adds a failure for the given host, updating its metrics and priority.
    pub fn add_failure(&self, host_key: PublicKey) {
        self.hosts.add_failure(host_key);
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
            let (prices, elapsed) = timeout(fetch_timeout, transport.host_prices(host_endpoint))
                .await
                .inspect_err(|_| hosts.add_failure(host_endpoint.public_key))?
                .inspect_err(|_| hosts.add_failure(host_endpoint.public_key))?;
            hosts.add_settings_sample(host_endpoint.public_key, elapsed);
            cache.set(host_endpoint.public_key, prices.clone());
            Ok((prices, true))
        }
    }

    pub async fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: bytes::Bytes,
        write_timeout: Duration,
    ) -> Result<Hash256, RPCError> {
        let host = self.host_endpoint(host_key)?;
        let _inflight = self.hosts.track_inflight_upload(&host_key);
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
            let bytes = sector.len() as u64;
            let (root, elapsed) = self
                .transport
                .write_sector(&host, prices, account_key, sector)
                .await
                .inspect_err(|_| self.hosts.add_failure(host_key))
                .map_err(RPCError::Rhp)?;
            self.hosts.add_write_sample(host_key, bytes, elapsed);
            Ok(root)
        })
        .await?
    }

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
        let bytes = length as u64;
        let _inflight = self.hosts.track_inflight_download(&host_key);
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
            self.hosts.add_read_sample(host_key, bytes, elapsed);
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

    cross_target_tests! {
    async fn test_failure_rate() {
        let mut fr = FailureRate::default();
        assert_eq!(fr.rate(), 0, "initial failure rate should be 0%");
        fr.add_sample(false);
        assert_eq!(fr.rate(), 100, "initial failure should be 100%");

        for _ in 0..5 {
            fr.add_sample(true);
        }
        assert!(
            fr.rate() < 100,
            "failure rate should decrease after successes"
        );

        let mut fr2 = FailureRate::default();
        for _ in 0..5 {
            fr2.add_sample(true);
        }
        assert_eq!(
            fr2.rate(),
            0,
            "failure rate should be 0% after only successes"
        );
        assert_eq!(
            fr.cmp(&fr2),
            std::cmp::Ordering::Greater,
            "higher failure rate should be greater"
        );
    }

    async fn test_rpc_average() {
        let mut avg = RPCAverage::default();
        assert_eq!(
            avg.avg(),
            None,
            "unsampled average should be None (no 1 Gbps default)"
        );

        avg.add_sample(100);
        assert_eq!(avg.avg(), Some(100.0), "initial average should be first sample");

        avg.add_sample(200);
        assert!(avg.avg() > Some(100.0), "average should increase after higher sample");

        avg.add_sample(50);
        assert!(avg.avg() < Some(200.0), "average should decrease after lower sample");
    }

    async fn test_host_metric_ordering() {
        // Sorting a list of HostMetric by HostScore (inflight=0) should
        // descend by failure_rate then by throughput.
        let mut hosts = vec![
            HostMetric::default(),
            HostMetric::default(),
            HostMetric::default(),
        ];
        hosts[0].failure_rate.add_sample(false);
        hosts[1].failure_rate.add_sample(false);
        hosts[2].failure_rate.add_sample(false);
        for _ in 0..10 {
            hosts[0].failure_rate.add_sample(true);
        }
        for _ in 0..5 {
            hosts[1].failure_rate.add_sample(true);
        }
        // Sort by HostScore ascending; reverse to get desc.
        hosts.sort_by(|a, b| HostScore::new(a, 0).cmp(&HostScore::new(b, 0)));
        let rates = hosts
            .into_iter()
            .rev()
            .map(|h| h.failure_rate)
            .collect::<Vec<FailureRate>>();
        assert!(
            rates.is_sorted(),
            "hosts should be sorted by failure rate desc"
        );

        let mut hosts = vec![
            HostMetric::default(),
            HostMetric::default(),
            HostMetric::default(),
        ];
        hosts[0].rpc_write_avg.add_sample(100);
        hosts[1].rpc_write_avg.add_sample(1000);
        hosts[2].rpc_write_avg.add_sample(500);
        hosts.sort_by(|a, b| HostScore::new(a, 0).cmp(&HostScore::new(b, 0)));
        let rates = hosts
            .into_iter()
            .rev()
            .map(|h| h.rpc_write_avg.avg())
            .collect::<Vec<Option<f64>>>();
        assert!(
            rates.is_sorted_by(|a, b| a >= b),
            "hosts should be sorted by rpc write avg desc"
        );
    }

    async fn test_host_ranking() {
        // End-to-end host ranking via HostScore at the metric layer.
        // All-unsampled, all-equal: HostScore::new with inflight=0 is the
        // pure-quality ranking and ties for hosts with no samples.
        let unsampled_a = HostScore::new(&HostMetric::default(), 0);
        let unsampled_b = HostScore::new(&HostMetric::default(), 0);
        assert_eq!(unsampled_a.cmp(&unsampled_b), std::cmp::Ordering::Equal);

        // Sample one host: unsampled now outranks it (discovery preference).
        let sampled_slow = {
            let mut m = HostMetric::default();
            m.add_write_sample(100, Duration::from_secs(1));
            m
        };
        let sampled_slow_score = HostScore::new(&sampled_slow, 0);
        assert!(
            unsampled_a > sampled_slow_score,
            "unsampled should outrank sampled (discovery)",
        );

        // Among sampled, faster wins.
        let sampled_fast = {
            let mut m = HostMetric::default();
            m.add_read_sample(1000, Duration::from_secs(1));
            m
        };
        let sampled_fast_score = HostScore::new(&sampled_fast, 0);
        assert!(sampled_fast_score > sampled_slow_score);

        // Failure trumps throughput.
        let failing_fast = {
            let mut m = sampled_fast.clone();
            m.add_failure();
            m
        };
        let failing_fast_score = HostScore::new(&failing_fast, 0);
        assert!(failing_fast_score < sampled_slow_score);
    }

    async fn test_next_upload_host() {
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
        // is never picked.
        let mut exclude = HashSet::new();
        let first = hosts_manager.next_upload_host(&exclude).unwrap();
        assert!(first == hk1 || first == hk3);
        assert_ne!(first, hk2);

        // Excluding the first picks the other upload-eligible host.
        exclude.insert(first);
        let second = hosts_manager.next_upload_host(&exclude).unwrap();
        assert!(second == hk1 || second == hk3);
        assert_ne!(second, first);
        assert_ne!(second, hk2);

        // Excluding both leaves nothing.
        exclude.insert(second);
        assert!(hosts_manager.next_upload_host(&exclude).is_none());
    }

    async fn test_host_score_orders_by_weighted_throughput() {
        // Same metric but different inflight: the less-loaded host wins.
        let metric = {
            let mut m = HostMetric::default();
            m.add_write_sample(1_000_000, Duration::from_secs(1));
            m
        };
        let busy = HostScore::new(&metric, 4);
        let idle = HostScore::new(&metric, 0);
        assert!(idle > busy, "less-loaded host should outrank busy host");

        // A 10x faster host beats an idle slow host even when it has some load.
        let fast_metric = {
            let mut m = HostMetric::default();
            m.add_write_sample(10_000_000, Duration::from_secs(1));
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

    async fn test_prioritize_uses_download_inflight() {
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
            .add_read_sample(hk1, 1_000_000, Duration::from_secs(1));
        hosts_manager
            .hosts
            .add_read_sample(hk2, 1_000_000, Duration::from_secs(1));

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
}
