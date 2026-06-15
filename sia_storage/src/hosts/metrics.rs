use std::fmt::Display;
use std::ops::Deref;

use crate::time::Duration;

#[derive(Debug, Default, Clone)]
pub(crate) struct RPCAverage(Option<TransferRate>); // exponential moving average of throughput in bytes/sec

impl RPCAverage {
    const ALPHA: f64 = 0.2;

    pub(super) fn add_sample(&mut self, rate: TransferRate) {
        match self.0 {
            Some(avg) => {
                self.0 = Some(Self::ALPHA * rate + (1.0 - Self::ALPHA) * avg);
            }
            None => {
                self.0 = Some(rate);
            }
        }
    }

    /// Returns the current average in bytes/sec, or `None` if no samples have
    /// been recorded yet. Callers decide how to treat unsampled hosts.
    pub(crate) fn avg(&self) -> Option<TransferRate> {
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
pub(crate) struct FailureRate(Option<f64>); // exponential moving average of failure rate

impl FailureRate {
    const ALPHA: f64 = 0.2;

    pub(super) fn add_sample(&mut self, success: bool) {
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
    pub(crate) fn rate(&self) -> i64 {
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
pub(super) struct HostMetric {
    rpc_write_avg: RPCAverage,
    rpc_read_avg: RPCAverage,
    failure_rate: FailureRate,
}

impl HostMetric {
    pub(super) fn add_write_sample(&mut self, transfer: Transfer) {
        self.rpc_write_avg.add_sample(transfer.rate());
        self.failure_rate.add_sample(true);
    }

    pub(super) fn add_read_sample(&mut self, transfer: Transfer) {
        self.rpc_read_avg.add_sample(transfer.rate());
        self.failure_rate.add_sample(true);
    }

    pub(super) fn add_failure(&mut self) {
        self.failure_rate.add_sample(false);
    }

    /// Combined read + write throughput average. `None` only when neither side
    /// has been sampled. Used by [`HostScore`] for the discovery preference
    /// (unsampled outranks sampled).
    pub(crate) fn combined_throughput(&self) -> Option<TransferRate> {
        match (self.rpc_write_avg.avg(), self.rpc_read_avg.avg()) {
            (None, None) => None,
            (Some(w), Some(r)) => Some((w + r) / 2.0),
            (Some(v), None) | (None, Some(v)) => Some(v),
        }
    }
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
pub(crate) struct HostScore {
    failure_rate: i64,
    throughput: Option<TransferRate>,
    inflight: usize,
}

impl HostScore {
    pub(super) fn new(metric: &HostMetric, inflight: usize) -> Self {
        Self {
            failure_rate: metric.failure_rate.rate(),
            throughput: metric.combined_throughput(),
            inflight,
        }
    }

    pub(crate) fn weighted_throughput(&self) -> Option<TransferRate> {
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
                (None, None) => other.inflight.cmp(&self.inflight),
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

/// A successful transfer observation: `size` bytes in `elapsed`. Validated
/// once at construction; [`Self::rate`] and [`Self::pace`] are views.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Transfer {
    size: u32,
    elapsed: Duration,
}

impl Transfer {
    pub const fn new(size: u32, elapsed: Duration) -> Self {
        Self::try_new(size, elapsed).expect("size and elapsed cannot be zero")
    }

    pub const fn try_new(size: u32, elapsed: Duration) -> Option<Self> {
        if size == 0 || elapsed.is_zero() {
            return None;
        }
        Some(Self { size, elapsed })
    }

    /// Returns the rate of the transfer in bytes per second.
    pub const fn rate(&self) -> TransferRate {
        TransferRate(self.size as f64 / self.elapsed.as_secs_f64())
    }

    /// Returns the per-byte latency of the transfer in seconds per byte.
    pub const fn pace(&self) -> TransferPace {
        TransferPace(self.elapsed.as_secs_f64() / self.size as f64)
    }

    /// Returns an estimate of the time it will take to transfer
    /// `size` bytes.
    pub fn estimate_duration(&self, size: u32) -> Duration {
        self.pace().estimate_duration(size)
    }
}

impl TransferPace {
    /// Returns an estimate of the time it will take to transfer
    /// `size` bytes at this pace.
    pub fn estimate_duration(&self, size: u32) -> Duration {
        Duration::from_secs_f64(self.0 * size as f64)
    }
}

/// The rate of a transfer in bytes per second.
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub(crate) struct TransferRate(f64);

/// The per-byte latency of a transfer in seconds per byte.
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub(crate) struct TransferPace(f64);

// macro for common implementations between pace and rate
macro_rules! impl_transfer {
    ($($t:ident),*) => {$(
        impl Deref for $t {
            type Target = f64;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl std::ops::Add for $t {
            type Output = Self;
            fn add(self, rhs: Self) -> Self {
                Self(self.0 + rhs.0)
            }
        }

        impl std::ops::Sub for $t {
            type Output = Self;
            fn sub(self, rhs: Self) -> Self {
                Self(self.0 - rhs.0)
            }
        }

        impl std::ops::Add<f64> for $t {
            type Output = Self;
            fn add(self, rhs: f64) -> Self {
                Self(self.0 + rhs)
            }
        }

        impl std::ops::Sub<f64> for $t {
            type Output = Self;
            fn sub(self, rhs: f64) -> Self {
                Self(self.0 - rhs)
            }
        }

        impl std::ops::Mul<f64> for $t {
            type Output = Self;
            fn mul(self, rhs: f64) -> Self {
                Self(self.0 * rhs)
            }
        }

        impl std::ops::Div<f64> for $t {
            type Output = Self;
            fn div(self, rhs: f64) -> Self {
                Self(self.0 / rhs)
            }
        }

        impl std::ops::Add<$t> for f64 {
            type Output = $t;
            fn add(self, rhs: $t) -> $t {
                $t(self + rhs.0)
            }
        }

        impl std::ops::Sub<$t> for f64 {
            type Output = $t;
            fn sub(self, rhs: $t) -> $t {
                $t(self - rhs.0)
            }
        }

        impl std::ops::Mul<$t> for f64 {
            type Output = $t;
            fn mul(self, rhs: $t) -> $t {
                $t(self * rhs.0)
            }
        }

        impl std::ops::Div<$t> for f64 {
            type Output = $t;
            fn div(self, rhs: $t) -> $t {
                $t(self / rhs.0)
            }
        }
    )*};
}

impl_transfer!(TransferRate, TransferPace);

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[sia_core_derive::cross_target_test]
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
            "unsampled average should be None (no 1 Gbps default)"
        );

        avg.add_sample(Transfer::new(100, Duration::from_secs(1)).rate());
        assert_eq!(
            avg.avg(),
            Some(Transfer::new(100, Duration::from_secs(1)).rate()),
            "initial average should be first sample"
        );

        avg.add_sample(Transfer::new(200, Duration::from_secs(1)).rate());
        assert!(
            avg.avg() > Some(Transfer::new(100, Duration::from_secs(1)).rate()),
            "average should increase after higher sample"
        );

        avg.add_sample(Transfer::new(50, Duration::from_secs(1)).rate());
        assert!(
            avg.avg() < Some(Transfer::new(200, Duration::from_secs(1)).rate()),
            "average should decrease after lower sample"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_host_metric_ordering() {
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
        hosts[0]
            .rpc_write_avg
            .add_sample(Transfer::new(100, Duration::from_secs(1)).rate());
        hosts[1]
            .rpc_write_avg
            .add_sample(Transfer::new(1000, Duration::from_secs(1)).rate());
        hosts[2]
            .rpc_write_avg
            .add_sample(Transfer::new(500, Duration::from_secs(1)).rate());
        hosts.sort_by(|a, b| HostScore::new(a, 0).cmp(&HostScore::new(b, 0)));
        let rates = hosts
            .into_iter()
            .rev()
            .map(|h| h.rpc_write_avg.avg())
            .collect::<Vec<_>>();
        assert!(
            rates.is_sorted_by(|a, b| a >= b),
            "hosts should be sorted by rpc write avg desc"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_host_ranking() {
        // End-to-end host ranking via HostScore at the metric layer.
        // All-unsampled, all-equal: HostScore::new with inflight=0 is the
        // pure-quality ranking and ties for hosts with no samples.
        let unsampled_a = HostScore::new(&HostMetric::default(), 0);
        let unsampled_b = HostScore::new(&HostMetric::default(), 0);
        assert_eq!(unsampled_a.cmp(&unsampled_b), std::cmp::Ordering::Equal);

        // Sample one host: unsampled now outranks it (discovery preference).
        let sampled_slow = {
            let mut m = HostMetric::default();
            m.add_write_sample(Transfer::new(100, Duration::from_secs(1)));
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
            m.add_read_sample(Transfer::new(1000, Duration::from_secs(1)));
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
}
