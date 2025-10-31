use std::collections::{HashMap, VecDeque};
use std::fmt::{Debug, Display};
use std::sync::Arc;
use std::time::Duration;

use priority_queue::PriorityQueue;
use sia::rhp::Host;
use sia::signing::PublicKey;
use sia::types::v2::NetAddress;
use std::sync::Mutex;
use thiserror::Error;

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

    fn add_failure(&mut self) {
        self.failure_rate.add_sample(false);
    }
}

impl Ord for HostMetric {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match other.failure_rate.cmp(&self.failure_rate) {
            // lower failure rate is higher priority
            std::cmp::Ordering::Equal => {
                // use average of read and write RPC times as tiebreaker
                let avg_self = (self
                    .rpc_write_avg
                    .avg()
                    .saturating_add(self.rpc_read_avg.avg()))
                    / 2;
                let avg_other = (other
                    .rpc_write_avg
                    .avg()
                    .saturating_add(other.rpc_read_avg.avg()))
                    / 2;
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
struct HostsInner {
    hosts: HashMap<PublicKey, Vec<NetAddress>>,
    preferred_hosts: PriorityQueue<PublicKey, HostMetric>,
}

/// Manages a list of known hosts and their performance metrics.
///
/// It allows updating the list of hosts, recording performance samples,
/// and prioritizing hosts based on their metrics.
///
/// It can be safely shared across threads and cloned.
#[derive(Debug, Clone)]
pub struct Hosts {
    inner: Arc<Mutex<HostsInner>>,
}

impl Default for Hosts {
    fn default() -> Self {
        Self::new()
    }
}

impl Hosts {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HostsInner {
                hosts: HashMap::new(),
                preferred_hosts: PriorityQueue::new(),
            })),
        }
    }

    pub fn addresses(&self, host_key: &PublicKey) -> Option<Vec<NetAddress>> {
        let inner = self.inner.lock().unwrap();
        inner.hosts.get(host_key).cloned()
    }

    /// Sorts a list of hosts according to their priority in the client's
    /// preferred hosts queue. The function `f` is used to extract the
    /// public key from each item.
    pub fn prioritize<H, F>(&self, hosts: &mut [H], f: F)
    where
        F: Fn(&H) -> &PublicKey,
    {
        let inner = self.inner.lock().unwrap();
        let preferred_hosts = &inner.preferred_hosts;
        hosts.sort_by(|a, b| {
            preferred_hosts
                .get_priority(f(b))
                .cmp(&preferred_hosts.get_priority(f(a)))
        });
    }

    /// Updates the list of known hosts.
    ///
    /// Existing hosts not in the new list are removed, but their metrics are retained
    /// in case they reappear later.
    pub fn update(&self, hosts: Vec<Host>) {
        let mut inner = self.inner.lock().unwrap();
        inner.hosts.clear();
        for host in hosts {
            inner.hosts.insert(host.public_key, host.addresses);
            if !inner.preferred_hosts.contains(&host.public_key) {
                inner
                    .preferred_hosts
                    .push(host.public_key, HostMetric::default());
            }
        }
    }

    /// Records a read RPC sample for the given host.
    pub fn add_read_sample(&self, host_key: &PublicKey, duration: Duration) {
        let mut inner = self.inner.lock().unwrap();
        inner
            .preferred_hosts
            .change_priority_by(host_key, |metric| {
                metric.add_read_sample(duration);
            });
    }

    /// Records a write sample for the given host.
    pub fn add_write_sample(&self, host_key: &PublicKey, duration: Duration) {
        let mut inner = self.inner.lock().unwrap();
        inner
            .preferred_hosts
            .change_priority_by(host_key, |metric| {
                metric.add_write_sample(duration);
            });
    }

    /// Records a failure for the given host.
    pub fn add_failure(&self, host_key: &PublicKey) {
        let mut inner = self.inner.lock().unwrap();
        inner
            .preferred_hosts
            .change_priority_by(host_key, |metric| {
                metric.add_failure();
            });
    }

    pub fn available(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.hosts.len()
    }

    /// Returns a list of all known hosts, sorted by priority.
    pub fn hosts(&self) -> Vec<PublicKey> {
        let inner = self.inner.lock().unwrap();
        let preferred_hosts = &inner.preferred_hosts;
        let mut hosts = inner.hosts.iter().map(|h| *h.0).collect::<Vec<_>>();

        hosts.sort_by(|a, b| {
            preferred_hosts
                .get_priority(b)
                .cmp(&preferred_hosts.get_priority(a))
        });
        hosts
    }

    /// Creates a queue of hosts for sequential access sorted by priority.
    pub fn queue(&self) -> HostQueue {
        let hosts = self.hosts();
        HostQueue::new(hosts)
    }
}

#[derive(Debug, Error)]
pub enum QueueError {
    #[error("no more hosts available")]
    NoMoreHosts,
    #[error("client closed")]
    Closed,

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
pub struct HostQueue {
    inner: Arc<Mutex<HostQueueInner>>,
}

impl HostQueue {
    pub fn new(hosts: Vec<PublicKey>) -> Self {
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
    use sia::signing::PrivateKey;

    use super::*;

    #[test]
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

    #[test]
    fn test_rpc_average() {
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

    #[test]
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

    #[test]
    fn test_host_priority_queue() {
        let mut pq = PriorityQueue::<PublicKey, HostMetric>::new();
        let mut hosts = vec![];
        for _ in 0..5 {
            let pk = PrivateKey::from_seed(&rand::random()).public_key();
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
}
