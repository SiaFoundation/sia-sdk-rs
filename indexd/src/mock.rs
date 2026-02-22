use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use sia::rhp::{self, HostPrices};
use sia::signing::{PrivateKey, PublicKey, Signature};
use sia::types::{Currency, Hash256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::sleep;

use async_trait::async_trait;

use crate::rhp4::{self, RHP4Client};
use crate::{
    DownloadError, DownloadOptions, Downloader, Hosts, Object, PackedUpload, UploadError,
    UploadOptions, Uploader,
};

pub struct MockRHP4Client {
    sectors: RwLock<HashMap<PublicKey, HashMap<Hash256, Bytes>>>,
    slow_hosts: RwLock<HashSet<PublicKey>>,
    slow_delay: RwLock<Duration>,
}

impl MockRHP4Client {
    pub fn new() -> Self {
        Self {
            sectors: RwLock::new(HashMap::new()),
            slow_hosts: RwLock::new(HashSet::new()),
            slow_delay: RwLock::new(Duration::ZERO),
        }
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

#[async_trait]
impl RHP4Client for MockRHP4Client {
    async fn host_prices(&self, _: PublicKey, _: bool) -> Result<HostPrices, rhp4::Error> {
        Ok(HostPrices {
            contract_price: Currency::zero(),
            collateral: Currency::zero(),
            ingress_price: Currency::zero(),
            egress_price: Currency::zero(),
            storage_price: Currency::zero(),
            free_sector_price: Currency::zero(),
            tip_height: 0,
            signature: Signature::default(),
            valid_until: Utc::now() + chrono::Duration::days(1),
        })
    }

    async fn write_sector(
        &self,
        host_key: PublicKey,
        _: &PrivateKey,
        sector: Bytes,
    ) -> Result<Hash256, rhp4::Error> {
        // Check if this host is configured as slow
        let slow_delay = {
            let slow_hosts = self.slow_hosts.read().unwrap();
            if slow_hosts.contains(&host_key) {
                Some(*self.slow_delay.read().unwrap())
            } else {
                None
            }
        };
        if let Some(delay) = slow_delay {
            sleep(delay).await;
        }

        sleep(Duration::from_millis(3)).await; // simulate network latency ~ 10Gbps
        let sector_root = rhp::sector_root(&sector);
        let mut sectors = self.sectors.write().unwrap();
        let host_sectors = sectors.entry(host_key).or_default();
        host_sectors.insert(sector_root, sector);
        Ok(sector_root)
    }

    async fn read_sector(
        &self,
        host_key: PublicKey,
        _: &PrivateKey,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<Bytes, rhp4::Error> {
        // Check if this host is configured as slow
        let slow_delay = {
            let slow_hosts = self.slow_hosts.read().unwrap();
            if slow_hosts.contains(&host_key) {
                Some(*self.slow_delay.read().unwrap())
            } else {
                None
            }
        };
        if let Some(delay) = slow_delay {
            sleep(delay).await;
        }

        let sector = {
            let sectors = self.sectors.read().unwrap();
            let host_sectors = sectors
                .get(&host_key)
                .ok_or_else(|| rhp4::Error::Transport("host not found".to_string()))?;
            let sector = host_sectors
                .get(&root)
                .ok_or_else(|| rhp4::Error::Transport("sector not found".to_string()))?;
            sector.slice(offset..offset + length)
        };
        sleep(Duration::from_nanos(sector.len() as u64 * 8 / 10)).await; // simulate network latency ~ 10Gbps
        Ok(sector)
    }
}

pub struct MockUploader {
    uploader: Uploader,
}

impl MockUploader {
    pub fn new(hosts: Hosts, client: Arc<MockRHP4Client>, app_key: Arc<PrivateKey>) -> Self {
        Self {
            uploader: Uploader::new(hosts, client.clone(), app_key),
        }
    }

    pub async fn upload<R: AsyncRead + Send + Sync + Unpin + 'static>(
        &self,
        r: R,
        options: UploadOptions,
    ) -> Result<Object, UploadError> {
        self.uploader.upload(r, options).await
    }

    pub fn upload_packed(&self, options: UploadOptions) -> PackedUpload {
        self.uploader.upload_packed(options)
    }
}

pub struct MockDownloader {
    downloader: Downloader,
}

impl MockDownloader {
    pub fn new(hosts: Hosts, client: Arc<MockRHP4Client>, app_key: Arc<PrivateKey>) -> Self {
        Self {
            downloader: Downloader::new(hosts, client.clone(), app_key),
        }
    }

    pub async fn download<W: AsyncWrite + Send + Sync + Unpin>(
        &self,
        w: &mut W,
        object: &Object,
        options: DownloadOptions,
    ) -> Result<(), DownloadError> {
        self.downloader.download(w, object, options).await
    }
}
