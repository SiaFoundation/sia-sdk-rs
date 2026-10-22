use std::collections::HashMap;
use std::ops::Range;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use chrono::Utc;
use sia_core::rhp4::{HostPrices, SECTOR_SIZE};
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;
use tokio::sync::watch;

use self::metrics::{HostMetric, HostScore, RPCAverage, Transfer, TransferRate};
use self::prices::{PriceEntry, PriceFetch};
use crate::rhp4::{self, Error, HostEndpoint};
use crate::task::AbortOnDropHandle;
use crate::time::Duration;
use crate::tokens::AccountTokenSource;

pub(crate) mod metrics;
mod pool;
mod prices;
pub(crate) use pool::default_client;

// A Client interacts with hosts and records performance metrics and failures. It is shared
// between all SDK instances.
#[derive(Clone)]
pub(crate) struct Client {
    transport: rhp4::Client,
    metrics: Arc<Metrics>,
    prices: prices::PriceCache,
}

#[derive(Debug, Default)]
pub(crate) struct Metrics {
    hosts: RwLock<HashMap<PublicKey, HostMetric>>,
    global_write_avg: RwLock<RPCAverage>,
    global_read_avg: RwLock<RPCAverage>,
}

#[cfg(test)]
#[derive(Debug, PartialEq)]
pub(crate) struct TransferRates {
    pub(crate) read: Option<TransferRate>,
    pub(crate) write: Option<TransferRate>,
}

impl Metrics {
    fn with_metric(&self, host: PublicKey, f: impl FnOnce(&mut HostMetric)) {
        f(self.hosts.write().unwrap().entry(host).or_default());
    }

    pub(crate) fn record_transfer(
        &self,
        host: PublicKey,
        read: Option<TransferRate>,
        write: Option<TransferRate>,
    ) {
        let read = read.filter(|rate| **rate > 0.0);
        let write = write.filter(|rate| **rate > 0.0);
        if read.is_none() && write.is_none() {
            return;
        }
        self.with_metric(host, |metric| {
            if let Some(rate) = read {
                metric.add_read_throughput(rate);
            }
            if let Some(rate) = write {
                metric.add_write_throughput(rate);
            }
        });
        if let Some(rate) = read {
            self.global_read_avg.write().unwrap().add_sample(rate);
        }
        if let Some(rate) = write {
            self.global_write_avg.write().unwrap().add_sample(rate);
        }
    }

    pub(crate) fn record_result<T>(
        &self,
        host: PublicKey,
        result: Result<T, Error>,
    ) -> Result<T, Error> {
        match &result {
            Ok(_) => self.with_metric(host, |metric| metric.add_success()),
            Err(Error::NoToken(_)) => {}
            Err(_) => self.with_metric(host, |metric| metric.add_failure()),
        }
        result
    }

    #[cfg(test)]
    pub(crate) fn failure_rate(&self, host: PublicKey) -> i64 {
        self.hosts
            .read()
            .unwrap()
            .get(&host)
            .map(HostMetric::failure_rate)
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn transfer_rates(&self) -> TransferRates {
        TransferRates {
            read: self.global_read_avg.read().unwrap().avg(),
            write: self.global_write_avg.read().unwrap().avg(),
        }
    }

    #[cfg(test)]
    fn add_failure(&self, host: PublicKey) {
        self.with_metric(host, |metric| metric.add_failure());
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("metrics", &self.metrics)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub(crate) fn new() -> Self {
        Self::with_transport(rhp4::Client::new())
    }

    fn with_transport(transport: rhp4::Client) -> Self {
        Self {
            transport,
            metrics: Arc::default(),
            prices: prices::PriceCache::default(),
        }
    }

    #[cfg(any(test, feature = "mock"))]
    pub(crate) fn from_mock(transport: rhp4::mock::Client) -> Self {
        Self::with_transport(rhp4::Client::Mock(transport))
    }

    pub(crate) fn host_score(&self, host: &PublicKey, inflight: usize) -> HostScore {
        let metrics = self.metrics.hosts.read().unwrap();
        HostScore::new(
            metrics.get(host).unwrap_or(&HostMetric::default()),
            inflight,
        )
    }

    /// Expected duration of a `bytes`-sized write on a typical host.
    /// Falls back to a static until the first write is sampled.
    pub fn write_estimate(&self, bytes: u32) -> Duration {
        const DEFAULT: Transfer = Transfer::new(SECTOR_SIZE as u32, Duration::from_secs(5));
        self.metrics
            .global_write_avg
            .read()
            .unwrap()
            .avg()
            .and_then(|rate| rate.pace())
            .map(|pace| pace.estimate_duration(bytes))
            .unwrap_or_else(|| DEFAULT.estimate_duration(bytes))
    }

    /// Expected duration of a `bytes`-sized read on a typical host.
    /// Falls back to a static until the first read is sampled.
    pub fn read_estimate(&self, bytes: u32) -> Duration {
        const DEFAULT: Transfer = Transfer::new(1 << 20, Duration::from_secs(1));
        self.metrics
            .global_read_avg
            .read()
            .unwrap()
            .avg()
            .and_then(|rate| rate.pace())
            .map(|pace| pace.estimate_duration(bytes))
            .unwrap_or_else(|| DEFAULT.estimate_duration(bytes))
    }

    fn start_price_fetch(&self, host: &HostEndpoint) -> Arc<PriceFetch> {
        let host = HostEndpoint {
            public_key: host.public_key,
            addresses: host.addresses.clone(),
        };
        let transport = self.transport.clone();
        let metrics = self.metrics.clone();
        let entries = self.prices.entries.clone();
        let (tx, outcome) = watch::channel(None);
        let task = maybe_spawn!(async move {
            let outcome = transport.host_prices(&host, metrics).await;
            if let Ok(prices) = &outcome {
                entries
                    .lock()
                    .unwrap()
                    .insert(host.public_key, PriceEntry::Cached(prices.clone()));
            }
            let _ = tx.send(Some(outcome));
        });
        Arc::new(PriceFetch {
            outcome,
            _task: AbortOnDropHandle::new(task),
        })
    }

    /// Returns the host's prices, fetching them when none are cached, the
    /// cached ones have expired. Concurrent calls for
    /// the same host wait on the in-flight fetch and share its outcome,
    /// success or failure.
    pub(crate) async fn host_prices(
        &self,
        host: &HostEndpoint,
    ) -> Result<HostPrices, crate::rhp4::Error> {
        let fetch = {
            let mut entries = self.prices.entries.lock().unwrap();
            match entries.get(&host.public_key) {
                Some(PriceEntry::Cached(prices)) if prices.valid_until > Utc::now() => {
                    return Ok(prices.clone());
                }
                // a finished fetch still held by its waiters has failed; start over
                Some(PriceEntry::Fetching(fetch))
                    if let Some(fetch) = fetch.upgrade()
                        && fetch.outcome.borrow().is_none() =>
                {
                    fetch
                }
                _ => {
                    let fetch = self.start_price_fetch(host);
                    entries.insert(
                        host.public_key,
                        PriceEntry::Fetching(Arc::downgrade(&fetch)),
                    );
                    fetch
                }
            }
        };
        let mut outcome = fetch.outcome.clone();
        let outcome = outcome
            .wait_for(Option::is_some)
            .await
            .map_err(|_| crate::rhp4::Error::Transport("price fetch exited".to_string()))?;
        outcome.as_ref().expect("waited for an outcome").clone()
    }

    pub(crate) async fn write_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        account_key: &PrivateKey,
        sector: Bytes,
    ) -> Result<Hash256, Error> {
        self.transport
            .write_sector(host, prices, account_key, sector, self.metrics.clone())
            .await
    }

    pub(crate) async fn read_sector(
        &self,
        host: &HostEndpoint,
        prices: HostPrices,
        tokens: &AccountTokenSource,
        root: Hash256,
        range: Range<usize>,
    ) -> Result<Bytes, Error> {
        self.transport
            .read_sector(host, prices, tokens, root, range, self.metrics.clone())
            .await
    }
}

#[cfg(test)]
impl Client {
    pub(crate) fn mock() -> Self {
        Self::with_transport(rhp4::Client::mock())
    }

    pub(crate) fn expire_host_prices(&self, host: PublicKey) {
        if let Some(PriceEntry::Cached(prices)) = self.prices.entries.lock().unwrap().get_mut(&host)
        {
            prices.valid_until = Utc::now() - chrono::Duration::seconds(1);
        }
    }

    pub(crate) fn failure_rate(&self, host: PublicKey) -> i64 {
        self.metrics.failure_rate(host)
    }

    pub(crate) fn seed_metric(&self, host: PublicKey, f: impl FnOnce(&mut HostMetric)) {
        self.metrics.with_metric(host, f);
    }

    pub(crate) fn seed_failure(&self, host: PublicKey) {
        self.metrics.add_failure(host);
    }

    /// Records a successful write for the host's metrics and the global
    /// write throughput EMA. Zero-size or zero-duration transfers are
    /// skipped rather than recorded as infinite throughput.
    fn record_write_sample(&self, host_key: PublicKey, size: u32, elapsed: Duration) {
        let Some(transfer) = Transfer::try_new(size, elapsed) else {
            return;
        };
        self.metrics
            .with_metric(host_key, |metric| metric.add_write_sample(transfer));
        self.metrics
            .global_write_avg
            .write()
            .unwrap()
            .add_sample(transfer.rate());
    }

    /// Read equivalent of [`Self::record_write_sample`].
    fn record_read_sample(&self, host_key: PublicKey, size: u32, elapsed: Duration) {
        let Some(transfer) = Transfer::try_new(size, elapsed) else {
            return;
        };
        self.metrics
            .with_metric(host_key, |metric| metric.add_read_sample(transfer));
        self.metrics
            .global_read_avg
            .write()
            .unwrap()
            .add_sample(transfer.rate());
    }

    pub(crate) fn seed_write_sample(&self, host: PublicKey, size: u32, elapsed: Duration) {
        self.record_write_sample(host, size, elapsed);
    }

    pub(crate) fn seed_read_sample(&self, host: PublicKey, size: u32, elapsed: Duration) {
        self.record_read_sample(host, size, elapsed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sia_core_derive::cross_target_test]
    async fn cancelled_rpc_without_progress_is_ignored() {
        let transport = rhp4::mock::Client::new();
        transport.set_price_delay(Duration::from_secs(60));
        let client = Client::from_mock(transport.clone());
        let host = HostEndpoint {
            public_key: PublicKey::new([1; 32]),
            addresses: vec![],
        };
        client.seed_write_sample(host.public_key, 1024, Duration::from_secs(1));
        let rate = || client.failure_rate(host.public_key);

        drop(client.host_prices(&host));
        assert_eq!(rate(), 0);

        let mut rpc = Box::pin(client.host_prices(&host));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(rpc.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        crate::time::timeout(Duration::from_secs(1), async {
            while transport.price_requests() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(rpc);
        tokio::task::yield_now().await;
        assert_eq!(rate(), 0);

        transport.set_price_delay(Duration::ZERO);
        client.host_prices(&host).await.unwrap();
        assert_eq!(rate(), 0);

        transport.set_price_failures(1);
        client.expire_host_prices(host.public_key);
        assert!(client.host_prices(&host).await.is_err());
        assert_eq!(rate(), 20);
    }
    #[sia_core_derive::cross_target_test]
    async fn cancelled_read_without_progress_is_ignored() {
        let transport = rhp4::mock::Client::new();
        let client = Client::from_mock(transport.clone());
        let host = HostEndpoint {
            public_key: PublicKey::new([1; 32]),
            addresses: vec![sia_core::types::v2::NetAddress {
                protocol: sia_core::types::v2::Protocol::SiaMux,
                address: "localhost:9984".into(),
            }],
        };
        let prices = client.host_prices(&host).await.unwrap();
        let tokens = AccountTokenSource::from(Arc::new(crate::AppKey::import([7; 32])));
        client.seed_read_sample(host.public_key, 1024, Duration::from_secs(1));
        transport.set_slow_hosts([host.public_key], Duration::from_secs(60));
        let estimate = client.read_estimate(1024);

        let mut rpc =
            Box::pin(client.read_sector(&host, prices, &tokens, Hash256::default(), 0..1024));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(rpc.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(rpc);
        assert_eq!(client.failure_rate(host.public_key), 0);
        assert_eq!(client.read_estimate(1024), estimate);
    }

    #[sia_core_derive::cross_target_test]
    async fn read_without_token_does_not_record_failure() {
        let client = Client::mock();
        let host = HostEndpoint {
            public_key: PublicKey::new([1; 32]),
            addresses: vec![sia_core::types::v2::NetAddress {
                protocol: sia_core::types::v2::Protocol::SiaMux,
                address: "localhost:9984".into(),
            }],
        };
        let prices = client.host_prices(&host).await.unwrap();
        let tokens = AccountTokenSource::Shared {
            tokens: Arc::default(),
            _refresh: Arc::new(crate::task::AbortOnDropHandle::new(maybe_spawn!(
                std::future::pending::<()>()
            ))),
        };
        client.seed_read_sample(host.public_key, 1024, Duration::from_secs(1));
        client.seed_failure(host.public_key);
        let estimate = client.read_estimate(1024);
        let result = client
            .read_sector(&host, prices, &tokens, Hash256::default(), 0..1024)
            .await;
        assert!(matches!(result, Err(Error::NoToken(key)) if key == host.public_key));
        assert_eq!(client.failure_rate(host.public_key), 20);
        assert_eq!(client.read_estimate(1024), estimate);
    }
    #[test]
    fn partial_samples_do_not_record_an_rpc_success() {
        let client = Client::mock();
        let host = PublicKey::new([1; 32]);
        client.seed_failure(host);
        client.metrics.record_transfer(
            host,
            TransferRate::try_new(1024, Duration::from_secs(1)),
            TransferRate::try_new(2048, Duration::from_secs(1)),
        );
        assert_eq!(client.failure_rate(host), 100);
        assert_eq!(client.read_estimate(1024), Duration::from_secs(1));
        assert_eq!(client.write_estimate(2048), Duration::from_secs(1));
    }

    #[test]
    fn zero_progress_does_not_change_metrics() {
        let client = Client::mock();
        let host = PublicKey::new([1; 32]);
        client.seed_read_sample(host, 1024, Duration::from_secs(1));
        client.seed_write_sample(host, 1024, Duration::from_secs(1));
        for _ in 0..250 {
            client.metrics.record_transfer(
                host,
                TransferRate::try_new(0, Duration::from_secs(2)),
                TransferRate::try_new(0, Duration::from_secs(2)),
            );
        }
        assert_eq!(client.failure_rate(host), 0);
        assert_eq!(client.read_estimate(1024), Duration::from_secs(1));
        assert_eq!(client.write_estimate(1024), Duration::from_secs(1));
    }

    #[test]
    fn stalled_direction_is_ignored_and_partial_progress_is_preserved() {
        let client = Client::mock();
        let host = PublicKey::new([1; 32]);
        client.seed_read_sample(host, 1024, Duration::from_secs(1));
        client.metrics.record_transfer(
            host,
            TransferRate::try_new(0, Duration::from_secs(2)),
            TransferRate::try_new(2048, Duration::from_secs(1)),
        );
        assert_eq!(client.failure_rate(host), 0);
        assert_eq!(client.read_estimate(1024), Duration::from_secs(1));
        assert_eq!(client.write_estimate(2048), Duration::from_secs(1));
    }

    #[test]
    fn missing_rates_are_ignored() {
        let client = Client::mock();
        let host = PublicKey::new([1; 32]);
        client.metrics.record_transfer(
            host,
            TransferRate::try_new(1024, Duration::ZERO),
            TransferRate::try_new(0, Duration::ZERO),
        );
        assert_eq!(client.failure_rate(host), 0);
    }

    #[test]
    fn idle_timeout_without_progress_records_failure() {
        let client = Client::mock();
        let host = PublicKey::new([1; 32]);
        client.seed_read_sample(host, 1024, Duration::from_secs(1));
        client.metrics.record_transfer(
            host,
            TransferRate::try_new(0, Duration::from_secs(2)),
            TransferRate::try_new(0, Duration::ZERO),
        );
        let result: Result<(), Error> =
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "stream idle").into());
        assert!(client.metrics.record_result(host, result).is_err());
        assert_eq!(client.failure_rate(host), 20);
        assert_eq!(client.read_estimate(1024), Duration::from_secs(1));
    }

    #[test]
    fn both_directions_record_one_rpc_outcome() {
        let client = Client::mock();
        let host = PublicKey::new([1; 32]);
        client.seed_failure(host);
        for success in [true, false] {
            client.metrics.record_transfer(
                host,
                TransferRate::try_new(1024, Duration::from_secs(1)),
                TransferRate::try_new(2048, Duration::from_secs(1)),
            );
            let result = if success {
                Ok(())
            } else {
                Err(Error::Transport("failed".into()))
            };
            assert_eq!(client.metrics.record_result(host, result).is_ok(), success);
            assert_eq!(client.failure_rate(host), if success { 80 } else { 84 });
        }
        assert_eq!(client.read_estimate(1024), Duration::from_secs(1));
        assert_eq!(client.write_estimate(2048), Duration::from_secs(1));
    }

    #[sia_core_derive::cross_target_test]
    async fn every_rpc_samples_both_directions() {
        let client = Client::mock();
        let host = HostEndpoint {
            public_key: PublicKey::new([1; 32]),
            addresses: vec![sia_core::types::v2::NetAddress {
                protocol: sia_core::types::v2::Protocol::SiaMux,
                address: "localhost:9984".into(),
            }],
        };
        let assert_and_reset = || {
            assert!(
                client
                    .metrics
                    .global_read_avg
                    .read()
                    .unwrap()
                    .avg()
                    .is_some()
            );
            assert!(
                client
                    .metrics
                    .global_write_avg
                    .read()
                    .unwrap()
                    .avg()
                    .is_some()
            );
            *client.metrics.global_read_avg.write().unwrap() = RPCAverage::default();
            *client.metrics.global_write_avg.write().unwrap() = RPCAverage::default();
        };
        let prices = client.host_prices(&host).await.unwrap();
        assert_and_reset();
        let account = PrivateKey::from_seed(&[7; 32]);
        let data = Bytes::from(vec![1; SECTOR_SIZE]);
        let root = client
            .write_sector(&host, prices.clone(), &account, data.clone())
            .await
            .unwrap();
        assert_and_reset();
        let tokens = AccountTokenSource::from(Arc::new(crate::AppKey::import([7; 32])));
        assert_eq!(
            client
                .read_sector(&host, prices, &tokens, root, 0..data.len())
                .await
                .unwrap(),
            data
        );
        assert_and_reset();
    }
}
