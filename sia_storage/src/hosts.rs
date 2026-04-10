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
use crate::task::TaskSet;

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
struct RPCAverage(Option<f64>); // exponential moving average of latency in milliseconds

impl RPCAverage {
    const ALPHA: f64 = 0.2;
    fn add_sample(&mut self, sample: Duration) {
        match self.0 {
            Some(avg) => {
                self.0 =
                    Some(Self::ALPHA * (sample.as_millis() as f64) + (1.0 - Self::ALPHA) * avg);
            }
            None => {
                self.0 = Some(sample.as_millis() as f64);
            }
        }
    }

    fn avg(&self) -> Duration {
        match self.0 {
            Some(avg) => Duration::from_millis(avg as u64),
            None => Duration::from_secs(3600), // 1h if no samples
        }
    }
}

impl Display for RPCAverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.avg().fmt(f)
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
        self.avg().cmp(&other.avg())
    }
}

impl PartialOrd for RPCAverage {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
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
    rpc_settings_avg: RPCAverage,
    rpc_write_avg: RPCAverage,
    rpc_read_avg: RPCAverage,
    failure_rate: FailureRate,
}

impl HostMetric {
    fn add_write_sample(&mut self, d: Duration) {
        self.rpc_write_avg.add_sample(d);
        self.failure_rate.add_sample(true);
    }

    fn add_read_sample(&mut self, d: Duration) {
        self.rpc_read_avg.add_sample(d);
        self.failure_rate.add_sample(true);
    }

    fn add_settings_sample(&mut self, d: Duration) {
        self.rpc_settings_avg.add_sample(d);
        self.failure_rate.add_sample(true);
    }

    fn add_failure(&mut self) {
        self.failure_rate.add_sample(false);
    }
}

impl Ord for HostMetric {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match other.failure_rate.cmp(&self.failure_rate) {
            // lower failure rate is higher priority
            std::cmp::Ordering::Equal => {
                // use average of read, write, and settings RPC times as tiebreaker
                let avg_self = (self
                    .rpc_write_avg
                    .avg()
                    .saturating_add(self.rpc_read_avg.avg()))
                .saturating_add(self.rpc_settings_avg.avg())
                    / 3;
                let avg_other = (other
                    .rpc_write_avg
                    .avg()
                    .saturating_add(other.rpc_read_avg.avg()))
                .saturating_add(other.rpc_settings_avg.avg())
                    / 3;
                avg_other.cmp(&avg_self) // lower average latency is higher priority
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
    /// their metrics are retained in case they reappear later.
    fn update(&self, new_hosts: Vec<Host>, clear: bool) {
        let mut hosts = self.hosts.write().unwrap();
        if clear {
            hosts.clear();
        }
        let mut priority = self.preferred_hosts.write().unwrap();
        for host in new_hosts {
            hosts.insert(
                host.public_key,
                HostInfo {
                    addresses: host.addresses,
                    good_for_upload: host.good_for_upload,
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

    /// Adds a read sample for the given host, updating its metrics and priority.
    fn add_read_sample(&self, host_key: PublicKey, duration: Duration) {
        self.preferred_hosts
            .write()
            .unwrap()
            .change_priority_by(&host_key, |metric| {
                metric.add_read_sample(duration);
            });
    }

    /// Adds a write sample for the given host, updating its metrics and priority.
    fn add_write_sample(&self, host_key: PublicKey, duration: Duration) {
        self.preferred_hosts
            .write()
            .unwrap()
            .change_priority_by(&host_key, |metric| {
                metric.add_write_sample(duration);
            });
    }

    fn add_settings_sample(&self, host_key: PublicKey, duration: Duration) {
        self.preferred_hosts
            .write()
            .unwrap()
            .change_priority_by(&host_key, |metric| {
                metric.add_settings_sample(duration);
            });
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
        let mut inflight_scans = TaskSet::new();
        let sema = Arc::new(Semaphore::new(15));
        for host in hosts {
            let transport = self.transport.clone();
            let price_cache = self.price_cache.clone();
            let hosts = self.hosts.clone();

            let sema = sema.clone();
            task_set_spawn!(inflight_scans, async move {
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
            let start = Instant::now();
            let prices = timeout(fetch_timeout, transport.host_prices(host_endpoint))
                .await
                .inspect_err(|_| hosts.add_failure(host_endpoint.public_key))?
                .inspect_err(|_| hosts.add_failure(host_endpoint.public_key))
                .inspect(|_| {
                    hosts.add_settings_sample(host_endpoint.public_key, start.elapsed())
                })?;
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
        let (prices, _) = Self::fetch_prices(
            self.transport.clone(),
            &self.price_cache,
            &self.hosts,
            &host,
            Duration::from_secs(1),
            false,
        )
        .await?;
        let start = Instant::now();
        timeout(
            write_timeout,
            self.transport
                .write_sector(&host, prices, account_key, sector),
        )
        .await
        .inspect_err(|_| self.hosts.add_failure(host_key))?
        .inspect_err(|_| self.hosts.add_failure(host_key))
        .inspect(|_| {
            self.hosts.add_write_sample(host_key, start.elapsed());
        })
        .map_err(RPCError::Rhp)
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
        let (prices, _) = Self::fetch_prices(
            self.transport.clone(),
            &self.price_cache,
            &self.hosts,
            &host,
            Duration::from_secs(1),
            false,
        )
        .await?;
        let start = Instant::now();
        timeout(
            read_timeout,
            self.transport
                .read_sector(&host, prices, account_key, root, offset, length),
        )
        .await
        .inspect_err(|_| self.hosts.add_failure(host_key))?
        .inspect_err(|_| self.hosts.add_failure(host_key))
        .inspect(|_| {
            self.hosts.add_read_sample(host_key, start.elapsed());
        })
        .map_err(RPCError::Rhp)
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
}

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
        self.pop_front().ok().map(|(host, _)| host)
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

    pub fn pop_front(&self) -> Result<(PublicKey, usize), QueueError> {
        let mut inner = self.inner.lock().map_err(|_| QueueError::MutexError)?;
        let host_key = inner.hosts.pop_front().ok_or(QueueError::NoMoreHosts)?;

        let attempts = inner.attempts.get(&host_key).cloned().unwrap_or(0);
        Ok((host_key, attempts + 1))
    }

    pub fn pop_n(&self, n: usize) -> Result<Vec<(PublicKey, usize)>, QueueError> {
        let mut inner = self.inner.lock().map_err(|_| QueueError::MutexError)?;
        if inner.hosts.len() < n {
            return Err(QueueError::NoMoreHosts);
        }
        let mut result = Vec::with_capacity(n);
        for _ in 0..n {
            let host_key = inner.hosts.pop_front().ok_or(QueueError::NoMoreHosts)?;
            let attempts = inner.attempts.get(&host_key).cloned().unwrap_or(0);
            result.push((host_key, attempts + 1));
        }
        Ok(result)
    }

    pub fn retry(&self, host: PublicKey) -> Result<(), QueueError> {
        let mut inner = self.inner.lock().map_err(|_| QueueError::MutexError)?;
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
    use sia_core::signing::PrivateKey;

    use crate::mock::MockRHP4Transport;

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
        avg.add_sample(Duration::from_millis(100));
        assert_eq!(
            avg.avg(),
            Duration::from_millis(100),
            "initial average should be first sample"
        );

        avg.add_sample(Duration::from_millis(200));
        assert!(
            avg.avg() > Duration::from_millis(100),
            "average should increase after higher sample"
        );

        avg.add_sample(Duration::from_millis(50));
        assert!(
            avg.avg() < Duration::from_millis(200),
            "average should decrease after lower sample"
        );

        let mut avg2 = RPCAverage::default();
        avg2.add_sample(Duration::from_millis(150));
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
        hosts[0]
            .rpc_write_avg
            .add_sample(Duration::from_millis(100));
        hosts[1]
            .rpc_write_avg
            .add_sample(Duration::from_millis(1000));
        hosts[2]
            .rpc_write_avg
            .add_sample(Duration::from_millis(500));
        hosts.sort();

        let rates = hosts
            .into_iter()
            .rev()
            .map(|h| h.rpc_write_avg)
            .collect::<Vec<RPCAverage>>();
        assert!(
            rates.is_sorted(),
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

        // initially, the order is the same as insertion
        assert_eq!(pq.peek().unwrap().0, &hosts[0]);

        // fourth host has a sample, should have highest priority
        pq.change_priority_by(&hosts[3], |metric| {
            metric.add_write_sample(Duration::from_millis(100));
        });
        assert_eq!(pq.peek().unwrap().0, &hosts[3]);

        // add a faster sample to second host, should have higher priority than fourth
        pq.change_priority_by(&hosts[1], |metric| {
            metric.add_read_sample(Duration::from_millis(50));
        });
        assert_eq!(pq.peek().unwrap().0, &hosts[1]);

        // add a failure to the second host, should lower its priority below fourth
        pq.change_priority_by(&hosts[1], |metric| {
            metric.add_failure();
        });
        assert_eq!(pq.peek().unwrap().0, &hosts[3]);
    }

    async fn test_upload_queue() {
        let hosts_manager = Hosts::new(MockRHP4Transport::new());

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
        let (first, _) = queue.pop_front().unwrap();
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
        assert_eq!(popped[0].0, hosts[0]);
        assert_eq!(popped[1].0, hosts[1]);
        assert_eq!(popped[2].0, hosts[2]);

        // all should have attempts = 1
        assert!(popped.iter().all(|(_, attempts)| *attempts == 1));

        // pop remaining 2
        let popped = queue.pop_n(2).expect("should pop 2 hosts");
        assert_eq!(popped.len(), 2);
        assert_eq!(popped[0].0, hosts[3]);
        assert_eq!(popped[1].0, hosts[4]);

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
