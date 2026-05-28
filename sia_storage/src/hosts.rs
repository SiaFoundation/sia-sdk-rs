use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::sync::{Arc, RwLock};

use chrono::Utc;
use log::debug;
use rand::RngExt;
use rand::rngs::SmallRng;
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
    fn rate(&self) -> f64 {
        self.0.unwrap_or(0.0)
    }
}

impl Display for FailureRate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}%", self.rate())
    }
}

impl PartialOrd for FailureRate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FailureRate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rate().total_cmp(&other.rate())
    }
}

impl PartialEq for FailureRate {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for FailureRate {}

// Computes throughput in bytes/sec, returning None when elapsed is zero so that
// the sample is skipped instead of producing an invalid/infinite throughput
// value that would skew the moving average.
const fn bytes_per_sec(bytes: u64, elapsed: Duration) -> Option<u64> {
    if elapsed.is_zero() {
        return None;
    }
    Some((bytes as f64 / elapsed.as_secs_f64()) as u64)
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
}

#[derive(Copy, Clone, Default)]
struct Score(f64);

impl Ord for Score {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl PartialOrd for Score {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Score {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for Score {}

#[derive(Debug)]
struct HostInfo {
    addresses: Vec<NetAddress>,
    good_for_upload: bool,
}

#[derive(Debug)]
struct HostList {
    hosts: RwLock<HashMap<PublicKey, HostInfo>>,
    metrics: RwLock<HashMap<PublicKey, Mutex<HostMetric>>>,
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

    fn read_score(&self, host_key: &PublicKey) -> Option<Score> {
        const DISCOVERY_BYTES_PER_SEC: f64 = 125_000_000.0;
        const FAILURE_DECAY: f64 = -10.0;

        let metrics = self.metrics.read().unwrap();
        let metric = metrics.get(host_key)?.lock().unwrap();

        let throughput = metric.rpc_read_avg.avg().unwrap_or(DISCOVERY_BYTES_PER_SEC);
        Some(Score(
            throughput * (FAILURE_DECAY * metric.failure_rate.rate()).exp(),
        ))
    }

    fn write_score(&self, host_key: &PublicKey) -> Option<Score> {
        const DISCOVERY_BYTES_PER_SEC: f64 = 125_000_000.0;
        const FAILURE_DECAY: f64 = -6.0;

        let metrics = self.metrics.read().unwrap();
        let metric = metrics.get(host_key)?.lock().unwrap();

        let throughput = metric
            .rpc_write_avg
            .avg()
            .unwrap_or(DISCOVERY_BYTES_PER_SEC);
        Some(Score(
            throughput.sqrt() * (FAILURE_DECAY * metric.failure_rate.rate()).exp(),
        ))
    }

    /// Sorts a list of hosts according to their priority in the client's
    /// preferred hosts queue. The function `f` is used to extract the
    /// public key from each item.
    fn prioritize<H, F>(&self, hosts: &mut [H], f: F)
    where
        F: Fn(&H) -> &PublicKey,
    {
        hosts.sort_by_cached_key(|host| {
            std::cmp::Reverse(self.read_score(f(host)).unwrap_or_default())
        });
    }

    /// Adds new hosts to the list if they don't already exist.
    ///
    /// If `clear` is true, existing hosts not in the new list are removed, but
    /// their metrics are retained in case they reappear later.
    fn update(&self, new_hosts: Vec<Host>, clear: bool) {
        let mut hosts = self.hosts.write().unwrap();
        let mut metrics = self.metrics.write().unwrap();
        if clear {
            hosts.clear();
        }
        for host in new_hosts {
            hosts.insert(
                host.public_key,
                HostInfo {
                    addresses: host.addresses,
                    good_for_upload: host.good_for_upload,
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

    /// Creates a queue of hosts that are good to upload to for sequential
    /// access sorted by priority.
    fn upload_queue(self: Arc<Self>) -> HostQueue {
        let mut available_hosts = self
            .hosts
            .read()
            .unwrap()
            .iter()
            .filter_map(|(hk, h)| h.good_for_upload.then_some(*hk))
            .collect::<Vec<_>>();

        self.prioritize(&mut available_hosts, |hk| hk);
        HostQueue::new(self, available_hosts)
    }

    /// Adds a failure for the given host, updating its metrics and priority.
    fn add_failure(&self, host_key: &PublicKey) {
        let metrics = self.metrics.read().unwrap();
        if let Some(metric) = metrics.get(host_key) {
            metric.lock().unwrap().add_failure();
        }
    }

    /// Adds a read sample for the given host, updating its metrics and priority.
    fn add_read_sample(&self, host_key: &PublicKey, bytes: u64, elapsed: Duration) {
        let metrics = self.metrics.read().unwrap();
        if let Some(metric) = metrics.get(host_key) {
            metric.lock().unwrap().add_read_sample(bytes, elapsed);
        }
    }

    /// Adds a write sample for the given host, updating its metrics and priority.
    fn add_write_sample(&self, host_key: &PublicKey, bytes: u64, elapsed: Duration) {
        let metrics = self.metrics.read().unwrap();
        if let Some(metric) = metrics.get(host_key) {
            metric.lock().unwrap().add_write_sample(bytes, elapsed);
        }
    }

    fn add_settings_sample(&self, host_key: &PublicKey, elapsed: Duration) {
        let metrics = self.metrics.read().unwrap();
        if let Some(metric) = metrics.get(host_key) {
            metric.lock().unwrap().add_settings_sample(elapsed);
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
        self.hosts.clone().upload_queue()
    }

    /// Adds a failure for the given host, updating its metrics and priority.
    pub fn add_failure(&self, host_key: &PublicKey) {
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
                .inspect_err(|_| hosts.add_failure(&host_endpoint.public_key))?
                .inspect_err(|_| hosts.add_failure(&host_endpoint.public_key))?;
            hosts.add_settings_sample(&host_endpoint.public_key, elapsed);
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
                .inspect_err(|_| self.hosts.add_failure(&host_key))
                .map_err(RPCError::Rhp)?;
            self.hosts.add_write_sample(&host_key, bytes, elapsed);
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
                .inspect_err(|_| self.hosts.add_failure(&host_key))
                .map_err(RPCError::Rhp)?;
            self.hosts.add_read_sample(&host_key, bytes, elapsed);
            Ok(data)
        })
        .await?
    }
}

/// Maximum number of times a single host may be re-queued via
/// [`HostQueue::retry`] before it is dropped.
const MAX_RETRIES: usize = 3;

#[derive(Debug)]
pub(crate) struct HostQueue {
    hosts: Arc<HostList>,
    available: Vec<PublicKey>,
    attempts: HashMap<PublicKey, usize>,
    rng: SmallRng, // for testing
}

impl HostQueue {
    fn new(hosts: Arc<HostList>, available: Vec<PublicKey>) -> Self {
        Self {
            hosts,
            available,
            attempts: HashMap::new(),
            rng: rand::make_rng(),
        }
    }

    pub fn pick(&mut self) -> Option<PublicKey> {
        if self.available.is_empty() {
            return None;
        }
        let mut best: Option<(usize, f64)> = None;
        for (i, pk) in self.available.iter().enumerate() {
            let score = self.hosts.write_score(pk).unwrap_or_default();
            let score = score.0.max(f64::MIN_POSITIVE).ln().max(1.0);
            let score = self.rng.random::<f64>().powf(1.0 / score);
            match best {
                None => best = Some((i, score)),
                Some((_, bs)) if score > bs => best = Some((i, score)),
                _ => {}
            }
        }
        let (i, _) = best?;
        let picked = self.available.swap_remove(i);
        Some(picked)
    }

    pub fn len(&self) -> usize {
        self.available.len()
    }

    pub fn retry(&mut self, host: PublicKey) -> bool {
        let attempts = self.attempts.entry(host).or_default();
        *attempts += 1;
        if *attempts >= MAX_RETRIES {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::rhp4::Client;
    use sia_core::signing::PrivateKey;

    fn random_pubkey() -> sia_core::signing::PublicKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        PrivateKey::from_seed(&seed).public_key()
    }

    fn test_host(public_key: PublicKey, good_for_upload: bool) -> Host {
        Host {
            public_key,
            addresses: vec![],
            country_code: String::new(),
            latitude: 0.0,
            longitude: 0.0,
            good_for_upload,
        }
    }

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[sia_core_derive::cross_target_test]
    fn test_failure_rate() {
        let mut fr = FailureRate::default();
        assert_eq!(fr.rate(), 0.0, "initial failure rate should be 0");

        fr.add_sample(false);
        assert_eq!(fr.rate(), 1.0, "single failure should give rate 1.0");

        for _ in 0..10 {
            fr.add_sample(true);
        }
        assert!(fr.rate() < 1.0, "failure rate should decay after successes");

        let mut clean = FailureRate::default();
        for _ in 0..5 {
            clean.add_sample(true);
        }
        assert_eq!(clean.rate(), 0.0, "rate stays 0 with only successes");
    }

    #[sia_core_derive::cross_target_test]
    fn test_rpc_average() {
        let mut avg = RPCAverage::default();
        assert_eq!(avg.avg(), None, "unsampled average should be None");

        avg.add_sample(100);
        assert_eq!(avg.avg(), Some(100.0), "first sample is the average");

        avg.add_sample(200);
        assert!(
            avg.avg().unwrap() > 100.0,
            "average increases with higher sample",
        );

        avg.add_sample(50);
        assert!(
            avg.avg().unwrap() < 200.0,
            "average decreases with lower sample",
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_write_score_uses_discovery_when_unsampled() {
        let hosts = Hosts::new(Client::new());
        let hk = random_pubkey();
        hosts.update(vec![test_host(hk, true)], true);

        let score = hosts
            .hosts
            .write_score(&hk)
            .expect("known host should score");
        assert!(score.0 > 0.0, "unsampled host gets the discovery baseline");

        assert!(
            hosts.hosts.write_score(&random_pubkey()).is_none(),
            "unknown host returns None",
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_score_drops_after_failures() {
        let hosts = Hosts::new(Client::new());
        let hk = random_pubkey();
        hosts.update(vec![test_host(hk, true)], true);

        let healthy = hosts.hosts.write_score(&hk).unwrap();
        for _ in 0..3 {
            hosts.add_failure(&hk);
        }
        let degraded = hosts.hosts.write_score(&hk).unwrap();
        assert!(
            degraded.0 < healthy.0,
            "failures should lower the score (was {} → {})",
            healthy.0,
            degraded.0,
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_upload_queue_filters_good_for_upload() {
        let hosts = Hosts::new(Client::new());
        let good = random_pubkey();
        let bad = random_pubkey();
        hosts.update(vec![test_host(good, true), test_host(bad, false)], true);

        let queue = hosts.upload_queue();
        assert_eq!(queue.len(), 1, "only good_for_upload hosts enter the queue");
    }

    #[sia_core_derive::cross_target_test]
    fn test_pick_returns_host_when_available() {
        // Regression: `best` was never initialized in `pick()`, so it always
        // returned None even with hosts available — surfacing as
        // `InsufficientHosts` at runtime.
        let hosts = Hosts::new(Client::new());
        let hk = random_pubkey();
        hosts.update(vec![test_host(hk, true)], true);

        let mut queue = hosts.upload_queue();
        assert_eq!(
            queue.pick(),
            Some(hk),
            "pick should return the only available host",
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_pick_drains_queue() {
        let hosts = Hosts::new(Client::new());
        let keys: Vec<_> = (0..5).map(|_| random_pubkey()).collect();
        hosts.update(keys.iter().map(|k| test_host(*k, true)).collect(), true);

        let mut queue = hosts.upload_queue();
        let mut picked = std::collections::HashSet::new();
        while let Some(hk) = queue.pick() {
            assert!(picked.insert(hk), "pick returned the same host twice");
        }
        assert_eq!(picked.len(), keys.len(), "every host picked exactly once");
        for k in &keys {
            assert!(picked.contains(k), "every input host appears in picks");
        }
    }

    #[sia_core_derive::cross_target_test]
    fn test_pick_empty_returns_none() {
        let hosts = Hosts::new(Client::new());
        let mut queue = hosts.upload_queue();
        assert_eq!(queue.pick(), None, "empty queue returns None");
    }

    #[sia_core_derive::cross_target_test]
    fn test_retry_caps_at_max() {
        let hosts = Hosts::new(Client::new());
        let mut queue = hosts.upload_queue();
        let hk = random_pubkey();

        assert!(queue.retry(hk), "first retry under cap");
        assert!(queue.retry(hk), "second retry under cap");
        assert!(!queue.retry(hk), "third retry exceeds MAX_RETRIES");
    }

    #[sia_core_derive::cross_target_test]
    fn test_prioritize_sorts_by_score_desc() {
        // After scoring, hosts with samples that produce higher scores should
        // sort ahead of less-favorable ones. We just check the relative order
        // of two hosts with sharply different metrics.
        let hosts = Hosts::new(Client::new());
        let fast = random_pubkey();
        let failing = random_pubkey();
        hosts.update(vec![test_host(fast, true), test_host(failing, true)], true);
        hosts
            .hosts
            .add_write_sample(&fast, 10_000_000, Duration::from_secs(1));
        for _ in 0..5 {
            hosts.hosts.add_failure(&failing);
        }

        let mut items = vec![failing, fast];
        hosts.prioritize(&mut items, |k| k);
        assert_eq!(items[0], fast, "fast healthy host should sort first");
        assert_eq!(items[1], failing, "failing host should sort last");
    }

    /*#[sia_core_derive::cross_target_test]
    fn test_failure_rate() {
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

    #[sia_core_derive::cross_target_test]
    fn test_rpc_average() {
        let mut avg = RPCAverage::default();
        assert_eq!(
            avg.avg(),
            None,
            "default average should be 1 Gbps before any samples"
        );

        avg.add_sample(100);
        assert_eq!(avg.avg(), Some(100.0), "initial average should be first sample");

        avg.add_sample(200);
        assert!(
            avg.avg().unwrap() > 100.0,
            "average should increase after higher sample"
        );

        avg.add_sample(50);
        assert!(
            avg.avg().unwrap() < 200.0,
            "average should decrease after lower sample"
        );

        let mut avg2 = RPCAverage::default();
        avg2.add_sample(150);
        assert_eq!(
            avg.avg().unwrap().total_cmp(&avg2.avg().unwrap()),
            std::cmp::Ordering::Less,
            "lower average should be lesser"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_host_metric_ordering() {
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

    #[sia_core_derive::cross_target_test]
    fn test_host_priority_queue() {
        let mut pq = PriorityQueue::<PublicKey, HostMetric>::new();
        let mut hosts = vec![];
        for _ in 0..5 {
            let pk = random_pubkey();
            pq.push(pk, HostMetric::default());
            hosts.push(pk);
        }

        // initially, the order is the same as insertion
        assert_eq!(pq.peek().unwrap().0, &hosts[0]);

        // fourth host gets a sample with throughput below the 1Gbps default,
        // dropping its priority below the other hosts
        pq.change_priority_by(&hosts[3], |metric| {
            metric.add_write_sample(100, Duration::from_secs(1));
        });
        assert_ne!(pq.peek().unwrap().0, &hosts[3]);

        // add a faster sample to second host, should have higher priority than fourth
        pq.change_priority_by(&hosts[1], |metric| {
            metric.add_read_sample(200, Duration::from_secs(1));
        });
        assert!(pq.get_priority(&hosts[1]).unwrap() > pq.get_priority(&hosts[3]).unwrap());

        // add a failure to the second host, should lower its priority below fourth
        pq.change_priority_by(&hosts[1], |metric| {
            metric.add_failure();
        });
        assert!(pq.get_priority(&hosts[1]).unwrap() < pq.get_priority(&hosts[3]).unwrap());
    }

    #[sia_core_derive::cross_target_test]
    fn test_upload_queue() {
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

    #[sia_core_derive::cross_target_test]
    fn test_host_queue_pop_n() {
        let hosts: Vec<_> = (0..5).map(|_| random_pubkey()).collect();
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

    #[sia_core_derive::cross_target_test]
    fn test_host_queue_pop_n_not_enough_hosts() {
        let hosts: Vec<_> = (0..3).map(|_| random_pubkey()).collect();
        let queue = HostQueue::new(hosts.clone());

        // try to pop more than available
        let result = queue.pop_n(5);
        assert!(matches!(result, Err(QueueError::NoMoreHosts)));

        // queue should be unchanged - can still pop all 3
        let popped = queue.pop_n(3).expect("should pop 3");
        assert_eq!(popped.len(), 3);
    }

    #[sia_core_derive::cross_target_test]
    fn test_host_queue_pop_n_zero() {
        let hosts: Vec<_> = (0..3).map(|_| random_pubkey()).collect();
        let queue = HostQueue::new(hosts);

        // pop 0 hosts should succeed with empty vec
        let popped = queue.pop_n(0).expect("should succeed");
        assert!(popped.is_empty());

        // queue should be unchanged - can still pop 3
        let popped = queue.pop_n(3).expect("should pop 3");
        assert_eq!(popped.len(), 3);
    }*/
}
