use std::collections::{HashMap, VecDeque};
use std::fmt::{Debug, Display};
use std::sync::{Arc, RwLock};

use chrono::Utc;
use log::debug;
use priority_queue::PriorityQueue;
use serde::{Deserialize, Serialize};
use sia_core::rhp4::HostPrices;
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;
use sia_core::types::v2::NetAddress;
use std::sync::Mutex;
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

    fn avg(&self) -> Option<u64> {
        self.0.map(|v| v as u64)
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

impl Ord for RPCAverage {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Treat unsampled as the lowest throughput so that sampled hosts —
        // even slow ones — win the tiebreaker over untested hosts. This stops
        // priority churning toward unknown hosts under load.
        self.avg().unwrap_or(0).cmp(&other.avg().unwrap_or(0))
    }
}

impl PartialOrd for RPCAverage {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Per-host aggregate-throughput tracker. Designed for parallel uploads where
/// dividing per-RPC bytes by per-RPC elapsed would penalize a host simply for
/// being used concurrently. Instead it credits bytes against the wall-clock
/// time during which the host was active (at least one inflight RPC), so 4
/// parallel uploads of 1.25 MB each finishing within 1 second produce a single
/// sample of 5 MB / 1s = 40 Mbps rather than four samples of 10 Mbps.
///
/// Bytes accumulate across an "active period" (host has inflight > 0). A
/// sample is emitted when the period ends (inflight returns to 0), or when
/// the period has been active for at least [`SAMPLE_ROTATION_PERIOD`] so
/// long-running busy hosts still get periodic EMA updates.
#[derive(Debug, Default)]
struct HostThroughput {
    inflight: usize,
    active_since: Option<Instant>,
    pending_bytes: u64,
}

impl HostThroughput {
    /// Maximum length of a sampling sub-period before forcing emission, so
    /// hosts that stay continuously busy keep updating the EMA.
    const SAMPLE_ROTATION_PERIOD: Duration = Duration::from_secs(2);

    fn started(&mut self) {
        if self.inflight == 0 {
            self.active_since = Some(Instant::now());
            self.pending_bytes = 0;
        }
        self.inflight += 1;
    }

    /// Records that an RPC finished. Pass `bytes` transferred on success or
    /// 0 on failure. Returns `Some((bytes, period))` when a throughput sample
    /// should be fed to the host's EMA.
    fn completed(&mut self, bytes: u64) -> Option<(u64, Duration)> {
        if self.inflight == 0 {
            return None; // unbalanced completed() call — ignore
        }
        self.pending_bytes = self.pending_bytes.saturating_add(bytes);
        self.inflight -= 1;

        let active_start = self.active_since?;
        let now = Instant::now();
        let period = now.duration_since(active_start);

        if self.inflight == 0 {
            // Period ending — emit the accumulated sample.
            self.active_since = None;
            if period.is_zero() {
                self.pending_bytes = 0;
                return None;
            }
            return Some((std::mem::take(&mut self.pending_bytes), period));
        }

        if period >= Self::SAMPLE_ROTATION_PERIOD {
            // Steady-state rotation so the EMA keeps updating.
            self.active_since = Some(now);
            return Some((std::mem::take(&mut self.pending_bytes), period));
        }

        None
    }
}

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

#[derive(Debug, Default, Clone, Eq, PartialEq)]
struct HostMetric {
    rpc_write_avg: RPCAverage,
    rpc_read_avg: RPCAverage,
    failure_rate: FailureRate,
}

impl HostMetric {
    /// Feeds a host-level aggregate-throughput sample (bytes/sec) to the
    /// write EMA. The caller computes this from a [`HostThroughput`] sample;
    /// it is no longer derived per-RPC.
    fn add_write_sample(&mut self, bytes_per_sec: u64) {
        self.rpc_write_avg.add_sample(bytes_per_sec);
    }

    /// Read-side analogue of [`Self::add_write_sample`].
    fn add_read_sample(&mut self, bytes_per_sec: u64) {
        self.rpc_read_avg.add_sample(bytes_per_sec);
    }

    fn record_success(&mut self) {
        self.failure_rate.add_sample(true);
    }

    fn add_failure(&mut self) {
        self.failure_rate.add_sample(false);
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

impl HostMetric {
    /// Combined throughput average for the throughput tiebreaker. Returns
    /// `None` only if both directions are unsampled, so a host that's been
    /// measured in either direction still ranks by its known throughput.
    fn combined_throughput(&self) -> Option<u64> {
        match (self.rpc_write_avg.avg(), self.rpc_read_avg.avg()) {
            (None, None) => None,
            (Some(w), Some(r)) => Some(w.saturating_add(r) / 2),
            (Some(v), None) | (None, Some(v)) => Some(v),
        }
    }
}

impl Ord for HostMetric {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match other.failure_rate.cmp(&self.failure_rate) {
            // lower failure rate is higher priority
            std::cmp::Ordering::Equal => {
                // Throughput tiebreaker, with a discovery preference: a host
                // that has never been sampled outranks any sampled host so
                // we eventually try every available host. Once a host has
                // at least one sample, it ranks by aggregate throughput.
                match (self.combined_throughput(), other.combined_throughput()) {
                    (None, None) => std::cmp::Ordering::Equal,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (Some(a), Some(b)) => a.cmp(&b),
                }
            }
            ord => ord,
        }
    }
}

impl PartialOrd for HostMetric {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
struct HostInfo {
    addresses: Vec<NetAddress>,
    good_for_upload: bool,
    upload_throughput: Arc<Mutex<HostThroughput>>,
    download_throughput: Arc<Mutex<HostThroughput>>,
}

#[derive(Debug)]
struct HostList {
    hosts: RwLock<HashMap<PublicKey, HostInfo>>,
    preferred_hosts: RwLock<PriorityQueue<PublicKey, HostMetric>>,
}

impl HostList {
    fn new() -> Self {
        Self {
            preferred_hosts: RwLock::new(PriorityQueue::new()),
            hosts: RwLock::new(HashMap::new()),
        }
    }

    fn addresses(&self, host_key: &PublicKey) -> Option<Vec<NetAddress>> {
        let hosts = self.hosts.read().unwrap();
        hosts.get(host_key).map(|h| h.addresses.clone())
    }

    /// Sorts a list of hosts according to their priority in the client's
    /// preferred hosts queue. The function `f` is used to extract the
    /// public key from each item.
    fn prioritize<H, F>(&self, hosts: &mut [H], f: F)
    where
        F: Fn(&H) -> &PublicKey,
    {
        let preferred_hosts = self.preferred_hosts.read().unwrap();
        hosts.sort_by(|a, b| {
            preferred_hosts
                .get_priority(f(b))
                .cmp(&preferred_hosts.get_priority(f(a)))
        });
    }

    /// Adds new hosts to the list if they don't already exist.
    ///
    /// If `clear` is true, existing hosts not in the new list are removed, but
    /// their metrics and throughput trackers are retained in case they reappear later.
    fn update(&self, new_hosts: Vec<Host>, clear: bool) {
        let mut hosts = self.hosts.write().unwrap();
        // When clearing, hold onto the existing entries so we can reuse their
        // throughput trackers for any host that's re-added in the same call —
        // matches the existing "retain metrics across clears" behavior.
        let old = if clear {
            std::mem::take(&mut *hosts)
        } else {
            HashMap::new()
        };
        let mut priority = self.preferred_hosts.write().unwrap();
        for host in new_hosts {
            let (upload_throughput, download_throughput) = match hosts
                .get(&host.public_key)
                .or_else(|| old.get(&host.public_key))
            {
                Some(existing) => (
                    existing.upload_throughput.clone(),
                    existing.download_throughput.clone(),
                ),
                None => (
                    Arc::new(Mutex::new(HostThroughput::default())),
                    Arc::new(Mutex::new(HostThroughput::default())),
                ),
            };
            hosts.insert(
                host.public_key,
                HostInfo {
                    addresses: host.addresses,
                    good_for_upload: host.good_for_upload,
                    upload_throughput,
                    download_throughput,
                },
            );
            if !priority.contains(&host.public_key) {
                priority.push(host.public_key, HostMetric::default());
            }
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

    /// Creates a queue of hosts that are good to upload to for sequential
    /// access sorted by priority.
    fn upload_queue(&self) -> HostQueue {
        let mut available_hosts = self
            .hosts
            .read()
            .unwrap()
            .iter()
            .filter_map(|(hk, h)| h.good_for_upload.then_some(*hk))
            .collect::<Vec<_>>();

        self.prioritize(&mut available_hosts, |hk| hk);
        HostQueue::new(available_hosts)
    }

    /// Adds a failure for the given host, updating its metrics and priority.
    fn add_failure(&self, host_key: PublicKey) {
        self.preferred_hosts
            .write()
            .unwrap()
            .change_priority_by(&host_key, |metric| {
                metric.add_failure();
            });
    }

    /// Marks a successful RPC for the given host without contributing a
    /// throughput sample (e.g. for settings/price fetches where the payload
    /// is too small to be a useful throughput signal).
    fn record_success(&self, host_key: PublicKey) {
        self.preferred_hosts
            .write()
            .unwrap()
            .change_priority_by(&host_key, |metric| {
                metric.record_success();
            });
    }

    fn upload_throughput(&self, host_key: &PublicKey) -> Option<Arc<Mutex<HostThroughput>>> {
        self.hosts
            .read()
            .unwrap()
            .get(host_key)
            .map(|h| h.upload_throughput.clone())
    }

    fn download_throughput(&self, host_key: &PublicKey) -> Option<Arc<Mutex<HostThroughput>>> {
        self.hosts
            .read()
            .unwrap()
            .get(host_key)
            .map(|h| h.download_throughput.clone())
    }

    /// Drains any pending throughput sample from the host's upload tracker
    /// and feeds it to the priority queue. Called after the inflight counter
    /// is updated on RPC completion.
    fn drain_upload_sample(&self, host_key: PublicKey, sample: Option<(u64, Duration)>) {
        if let Some((bytes, period)) = sample
            && let Some(bps) = bytes_per_sec(bytes, period)
        {
            self.preferred_hosts
                .write()
                .unwrap()
                .change_priority_by(&host_key, |metric| {
                    metric.add_write_sample(bps);
                });
        }
    }

    fn drain_download_sample(&self, host_key: PublicKey, sample: Option<(u64, Duration)>) {
        if let Some((bytes, period)) = sample
            && let Some(bps) = bytes_per_sec(bytes, period)
        {
            self.preferred_hosts
                .write()
                .unwrap()
                .change_priority_by(&host_key, |metric| {
                    metric.add_read_sample(bps);
                });
        }
    }
}

/// RAII guard for an in-flight upload to a host. Increments the host's
/// upload inflight counter on creation and decrements it on drop. Call
/// [`Self::record_success`] with the bytes transferred to mark a successful
/// upload; dropping without it leaves bytes uncredited and is the right
/// thing to do for a failed RPC (the caller separately calls `add_failure`
/// on `Hosts` to update the failure rate).
pub(crate) struct UploadGuard {
    host_list: Arc<HostList>,
    host_key: PublicKey,
    tracker: Arc<Mutex<HostThroughput>>,
    bytes: u64,
    success: bool,
}

impl UploadGuard {
    pub fn record_success(&mut self, bytes: u64) {
        self.bytes = bytes;
        self.success = true;
    }
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        let sample = self.tracker.lock().unwrap().completed(self.bytes);
        self.host_list.drain_upload_sample(self.host_key, sample);
        if self.success {
            self.host_list.record_success(self.host_key);
        }
    }
}

/// Download-side analogue of [`UploadGuard`].
pub(crate) struct DownloadGuard {
    host_list: Arc<HostList>,
    host_key: PublicKey,
    tracker: Arc<Mutex<HostThroughput>>,
    bytes: u64,
    success: bool,
}

impl DownloadGuard {
    pub fn record_success(&mut self, bytes: u64) {
        self.bytes = bytes;
        self.success = true;
    }
}

impl Drop for DownloadGuard {
    fn drop(&mut self) {
        let sample = self.tracker.lock().unwrap().completed(self.bytes);
        self.host_list.drain_download_sample(self.host_key, sample);
        if self.success {
            self.host_list.record_success(self.host_key);
        }
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

    /// Creates a queue of hosts that are good to upload to for sequential
    /// access sorted by priority.
    pub fn upload_queue(&self) -> HostQueue {
        self.hosts.upload_queue()
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
            let (prices, _elapsed) = timeout(fetch_timeout, transport.host_prices(host_endpoint))
                .await
                .inspect_err(|_| hosts.add_failure(host_endpoint.public_key))?
                .inspect_err(|_| hosts.add_failure(host_endpoint.public_key))?;
            // Settings/prices payloads are too small (~270 bytes) to be a
            // useful throughput signal under the aggregate-throughput model,
            // so just credit the success against the failure-rate EMA.
            hosts.record_success(host_endpoint.public_key);
            cache.set(host_endpoint.public_key, prices.clone());
            Ok((prices, true))
        }
    }

    /// Begins tracking an in-flight upload to `host_key`. Returns a guard
    /// whose Drop balances the inflight counter and emits a throughput
    /// sample if appropriate. Returns `None` if the host is unknown.
    fn upload_started(&self, host_key: PublicKey) -> Option<UploadGuard> {
        let tracker = self.hosts.upload_throughput(&host_key)?;
        tracker.lock().unwrap().started();
        Some(UploadGuard {
            host_list: self.hosts.clone(),
            host_key,
            tracker,
            bytes: 0,
            success: false,
        })
    }

    fn download_started(&self, host_key: PublicKey) -> Option<DownloadGuard> {
        let tracker = self.hosts.download_throughput(&host_key)?;
        tracker.lock().unwrap().started();
        Some(DownloadGuard {
            host_list: self.hosts.clone(),
            host_key,
            tracker,
            bytes: 0,
            success: false,
        })
    }

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
            let bytes = sector.len() as u64;
            let mut guard = self.upload_started(host_key);
            match self
                .transport
                .write_sector(&host, prices, account_key, sector)
                .await
            {
                Ok((root, _elapsed)) => {
                    if let Some(g) = guard.as_mut() {
                        g.record_success(bytes);
                    }
                    Ok(root)
                }
                Err(e) => {
                    // guard drops with bytes=0 / success=false, balancing
                    // inflight without crediting bytes to the throughput EMA.
                    self.hosts.add_failure(host_key);
                    Err(RPCError::Rhp(e))
                }
            }
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
            let mut guard = self.download_started(host_key);
            match self
                .transport
                .read_sector(&host, prices, account_key, root, offset, length)
                .await
            {
                Ok((data, _elapsed)) => {
                    if let Some(g) = guard.as_mut() {
                        g.record_success(data.len() as u64);
                    }
                    Ok(data)
                }
                Err(e) => {
                    self.hosts.add_failure(host_key);
                    Err(RPCError::Rhp(e))
                }
            }
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

/// Maximum number of times a single host may be re-queued via
/// [`HostQueue::retry`] before it is dropped.
const MAX_RETRIES: usize = 3;

#[derive(Debug)]
struct HostQueueInner {
    hosts: VecDeque<PublicKey>,
    attempts: HashMap<PublicKey, usize>,
}

/// A thread-safe queue of host public keys.
#[derive(Debug, Clone)]
pub(crate) struct HostQueue {
    inner: Arc<Mutex<HostQueueInner>>,
}

impl Iterator for HostQueue {
    type Item = PublicKey;

    fn next(&mut self) -> Option<Self::Item> {
        self.pop_front().ok()
    }
}

impl HostQueue {
    pub(crate) fn new(hosts: Vec<PublicKey>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HostQueueInner {
                hosts: VecDeque::from(hosts),
                attempts: HashMap::new(),
            })),
        }
    }

    pub fn pop_front(&self) -> Result<PublicKey, QueueError> {
        let mut inner = self.inner.lock().map_err(|_| QueueError::MutexError)?;
        inner.hosts.pop_front().ok_or(QueueError::NoMoreHosts)
    }

    pub fn pop_n(&self, n: usize) -> Result<Vec<PublicKey>, QueueError> {
        let mut inner = self.inner.lock().map_err(|_| QueueError::MutexError)?;
        if inner.hosts.len() < n {
            return Err(QueueError::NoMoreHosts);
        }
        let mut result = Vec::with_capacity(n);
        for _ in 0..n {
            let host_key = inner.hosts.pop_front().ok_or(QueueError::NoMoreHosts)?;
            result.push(host_key);
        }
        Ok(result)
    }

    pub fn retry(&self, host: PublicKey) -> Result<(), QueueError> {
        let mut inner = self.inner.lock().map_err(|_| QueueError::MutexError)?;
        let attempts = inner.attempts.get(&host).copied().unwrap_or(0);
        if attempts >= MAX_RETRIES {
            return Err(QueueError::MaxRetriesExceeded);
        }
        inner.hosts.push_back(host);
        inner
            .attempts
            .entry(host)
            .and_modify(|e| *e += 1)
            .or_insert(1);
        Ok(())
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
            "default average should be None before any samples"
        );

        avg.add_sample(100);
        assert_eq!(avg.avg(), Some(100), "initial average should be first sample");

        avg.add_sample(200);
        assert!(avg.avg() > Some(100), "average should increase after higher sample");

        avg.add_sample(50);
        assert!(avg.avg() < Some(200), "average should decrease after lower sample");

        // Unsampled is treated as 0 in cmp, so any sampled avg ranks above it.
        let unsampled = RPCAverage::default();
        assert!(
            avg > unsampled,
            "sampled avg should rank above unsampled"
        );

        let mut avg2 = RPCAverage::default();
        avg2.add_sample(150);
        assert_eq!(
            avg.cmp(&avg2),
            std::cmp::Ordering::Less,
            "lower average should be lesser"
        );
    }

    async fn test_host_metric_ordering() {
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
        hosts.sort();

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
        hosts.sort();

        let rates = hosts
            .into_iter()
            .rev()
            .map(|h| h.rpc_write_avg)
            .collect::<Vec<RPCAverage>>();
        assert!(
            rates.is_sorted_by(|a, b| a >= b),
            "hosts should be sorted by rpc write avg desc"
        );
    }

    async fn test_host_priority_queue() {
        let mut pq = PriorityQueue::<PublicKey, HostMetric>::new();
        let mut hosts = vec![];
        for _ in 0..5 {
            let pk = random_pubkey();
            pq.push(pk, HostMetric::default());
            hosts.push(pk);
        }

        // initially, the order is the same as insertion (all metrics equal)
        assert_eq!(pq.peek().unwrap().0, &hosts[0]);

        // Fourth host gets a sample. Unsampled hosts get discovery priority
        // and outrank any sampled host, so host[3] drops below the others.
        pq.change_priority_by(&hosts[3], |metric| {
            metric.add_write_sample(100);
        });
        assert_ne!(pq.peek().unwrap().0, &hosts[3]);

        // Sample host[1] as well. Both are sampled now; faster one ranks
        // above slower one.
        pq.change_priority_by(&hosts[1], |metric| {
            metric.add_read_sample(1000);
        });
        assert!(pq.get_priority(&hosts[1]).unwrap() > pq.get_priority(&hosts[3]).unwrap());

        // Unsampled hosts still beat both sampled hosts via discovery prio.
        assert!(pq.get_priority(&hosts[0]).unwrap() > pq.get_priority(&hosts[1]).unwrap());

        // Failure trumps throughput AND discovery, so host[1] now drops
        // below host[3] and below unsampled hosts.
        pq.change_priority_by(&hosts[1], |metric| {
            metric.add_failure();
        });
        assert!(pq.get_priority(&hosts[1]).unwrap() < pq.get_priority(&hosts[3]).unwrap());
        assert!(pq.get_priority(&hosts[1]).unwrap() < pq.get_priority(&hosts[0]).unwrap());
    }

    async fn test_host_throughput_aggregate() {
        // 4 streams overlap for ~50ms with 1.25 MB each. The single
        // end-of-period sample should credit all 5 MB against the wall-clock
        // period (not divide by stream count), matching the user's
        // 4-streams × 10 Mbps → 40 Mbps expectation.
        let mut t = HostThroughput::default();
        for _ in 0..4 {
            t.started();
        }
        crate::time::sleep(Duration::from_millis(50)).await;

        // First three completions are mid-period — no sample emitted.
        assert!(t.completed(1_250_000).is_none());
        assert!(t.completed(1_250_000).is_none());
        assert!(t.completed(1_250_000).is_none());
        // Final completion takes inflight to 0 and emits the period sample.
        let (bytes, period) = t.completed(1_250_000).expect("final completion should emit a sample");
        assert_eq!(bytes, 5_000_000, "all overlapping bytes counted toward the period");
        assert!(period >= Duration::from_millis(50));

        // Tracker is reset for the next period.
        assert_eq!(t.inflight, 0);
        assert_eq!(t.pending_bytes, 0);
        assert!(t.active_since.is_none());
    }

    async fn test_host_throughput_brief_overlap_no_inflate() {
        // A long upload with a brief burst at the end shouldn't see its
        // throughput inflated by the few-ms overlap. Bytes attributed
        // against the full active period, not just the overlap.
        let mut t = HostThroughput::default();
        t.started();
        crate::time::sleep(Duration::from_millis(100)).await;
        // Burst: 3 more start, all complete with tiny payloads.
        t.started();
        t.started();
        t.started();
        assert!(t.completed(100).is_none());
        assert!(t.completed(100).is_none());
        assert!(t.completed(100).is_none());
        // Long upload completes alone.
        let (bytes, period) = t.completed(1_000_000).expect("final completion should emit");
        assert_eq!(bytes, 1_000_300);
        assert!(period >= Duration::from_millis(100));
        let bps = bytes_per_sec(bytes, period).unwrap();
        // Even on an aggressively fast machine the bps reflects the full
        // active period rather than just the tail-end overlap window.
        assert!(bps < 50_000_000, "tail overlap inflated rate to {bps} bps");
    }

    async fn test_host_throughput_solo_upload() {
        let mut t = HostThroughput::default();
        t.started();
        crate::time::sleep(Duration::from_millis(50)).await;
        let (bytes, period) = t.completed(500_000).expect("solo completion emits");
        assert_eq!(bytes, 500_000);
        assert!(period >= Duration::from_millis(50));
    }

    async fn test_host_throughput_unbalanced_completed_is_safe() {
        let mut t = HostThroughput::default();
        // Completed without started — should be a no-op, not a panic.
        assert!(t.completed(100).is_none());
        assert_eq!(t.inflight, 0);
    }

    async fn test_upload_queue() {
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
                    good_for_upload: false,
                },
                Host {
                    public_key: hk2,
                    addresses: vec![],
                    country_code: String::new(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                },
                Host {
                    public_key: hk3,
                    addresses: vec![],
                    country_code: String::new(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: false,
                },
            ],
            true,
        );

        let queue = hosts_manager.upload_queue();
        let first = queue.pop_front().unwrap();
        assert_eq!(first, hk2);
        assert!(
            queue.pop_front().is_err(),
            "queue should only have one host"
        );
    }

    async fn test_host_queue_pop_n() {
        let hosts: Vec<_> = (0..5)
            .map(|_| random_pubkey())
            .collect();
        let queue = HostQueue::new(hosts.clone());

        // pop 3 hosts
        let popped = queue.pop_n(3).expect("should pop 3 hosts");
        assert_eq!(popped.len(), 3);
        assert_eq!(popped[0], hosts[0]);
        assert_eq!(popped[1], hosts[1]);
        assert_eq!(popped[2], hosts[2]);

        // pop remaining 2
        let popped = queue.pop_n(2).expect("should pop 2 hosts");
        assert_eq!(popped.len(), 2);
        assert_eq!(popped[0], hosts[3]);
        assert_eq!(popped[1], hosts[4]);

        // queue should be empty
        assert!(matches!(queue.pop_front(), Err(QueueError::NoMoreHosts)));
    }

    async fn test_host_queue_pop_n_not_enough_hosts() {
        let hosts: Vec<_> = (0..3)
            .map(|_| random_pubkey())
            .collect();
        let queue = HostQueue::new(hosts.clone());

        // try to pop more than available
        let result = queue.pop_n(5);
        assert!(matches!(result, Err(QueueError::NoMoreHosts)));

        // queue should be unchanged - can still pop all 3
        let popped = queue.pop_n(3).expect("should pop 3");
        assert_eq!(popped.len(), 3);
    }

    async fn test_host_queue_pop_n_zero() {
        let hosts: Vec<_> = (0..3)
            .map(|_| random_pubkey())
            .collect();
        let queue = HostQueue::new(hosts);

        // pop 0 hosts should succeed with empty vec
        let popped = queue.pop_n(0).expect("should succeed");
        assert!(popped.is_empty());

        // queue should be unchanged - can still pop 3
        let popped = queue.pop_n(3).expect("should pop 3");
        assert_eq!(popped.len(), 3);
    }
    }
}
