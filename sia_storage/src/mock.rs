use sia_core::signing::{PrivateKey, PublicKey};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::download::download_object;
use crate::hosts::Hosts;
use crate::rhp4::Client;
use crate::time::Duration;
use crate::upload::upload_slabs;
use crate::{DownloadError, DownloadOptions, Object, UploadError, UploadOptions};

pub struct MockUploader {
    hosts: Hosts,
    app_key: Arc<PrivateKey>,
}

impl MockUploader {
    pub fn new(hosts: MockHosts, app_key: Arc<PrivateKey>) -> Self {
        Self {
            hosts: hosts.inner,
            app_key,
        }
    }

    pub async fn upload<R: AsyncRead + Unpin + 'static>(
        &self,
        r: R,
        options: UploadOptions,
    ) -> Result<Object, UploadError> {
        let mut object = Object::default();
        let r = object.reader(r, 0);
        let new_slabs = upload_slabs(r, self.hosts.clone(), self.app_key.clone(), options).await?;
        object.slabs_mut().extend(new_slabs);
        Ok(object)
    }
}

pub struct MockDownloader {
    hosts: Hosts,
    app_key: Arc<PrivateKey>,
}

impl MockDownloader {
    pub fn new(hosts: MockHosts, app_key: Arc<PrivateKey>) -> Self {
        Self {
            hosts: hosts.inner,
            app_key,
        }
    }

    pub async fn download<W: AsyncWrite + Sync + Unpin>(
        &self,
        w: &mut W,
        object: &Object,
        options: DownloadOptions,
    ) -> Result<(), DownloadError> {
        download_object(self.hosts.clone(), self.app_key.clone(), w, object, options).await
    }
}

#[derive(Clone)]
pub struct MockHosts {
    transport: Client,
    inner: Hosts,
}

impl MockHosts {
    pub fn new() -> Self {
        let transport = Client::new();
        let hosts = Hosts::new(transport.clone());
        Self {
            transport: transport,
            inner: hosts,
        }
    }

    pub fn update(&self, hosts: Vec<crate::Host>, clear: bool) {
        self.inner.update(hosts, clear);
    }

    pub fn clear(&self) {
        self.transport.clear();
    }

    /// Sets the given hosts as "slow" - they will sleep for the specified duration
    /// before completing any write_sector or read_sector operation.
    pub fn set_slow_hosts(&self, hosts: impl IntoIterator<Item = PublicKey>, delay: Duration) {
        self.transport.set_slow_hosts(hosts, delay);
    }

    /// Clears all slow host settings.
    pub fn reset_slow_hosts(&self) {
        self.transport.reset_slow_hosts();
    }
}
