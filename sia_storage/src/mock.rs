use std::sync::Arc;

use sia_core::signing::PublicKey;
use tokio::io::AsyncRead;

use crate::download::Download;
use crate::hosts::Hosts;
use crate::rhp4::Client;
use crate::time::Duration;
use crate::upload::Uploader;
use crate::{AppKey, DownloadOptions, Object, PackedUpload, UploadError, UploadOptions};

pub struct MockUploader {
    uploader: Uploader<Client>,
}

impl MockUploader {
    pub fn new(hosts: MockHosts, app_key: Arc<AppKey>) -> Self {
        Self {
            uploader: Uploader::new(hosts.inner, app_key),
        }
    }

    pub async fn upload<R: AsyncRead + Send + Sync + Unpin + 'static>(
        &self,
        object: Object,
        r: R,
        options: UploadOptions,
    ) -> Result<Object, UploadError> {
        self.uploader.upload(object, r, options).await
    }

    pub fn upload_packed(&self, options: UploadOptions) -> PackedUpload {
        self.uploader.upload_packed(options)
    }
}

pub struct MockDownloader {
    hosts: MockHosts,
    app_key: Arc<AppKey>,
}

impl MockDownloader {
    pub fn new(hosts: MockHosts, app_key: Arc<AppKey>) -> Self {
        Self { hosts, app_key }
    }

    pub fn download(
        &self,
        object: &Object,
        options: DownloadOptions,
    ) -> impl tokio::io::AsyncRead + Unpin {
        Download::new(
            object,
            self.hosts.inner.clone(),
            self.app_key.clone(),
            options,
        )
    }
}

#[derive(Clone)]
pub struct MockHosts {
    transport: Client,
    pub(crate) inner: Hosts<Client>,
}

impl MockHosts {
    pub fn new() -> Self {
        let transport = Client::new();
        let hosts = Hosts::new(transport.clone());
        Self {
            transport,
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

impl Default for MockHosts {
    fn default() -> Self {
        Self::new()
    }
}
