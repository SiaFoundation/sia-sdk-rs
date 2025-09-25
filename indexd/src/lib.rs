pub mod app_client;
mod slabs;

pub mod quic;
use crate::quic::{
    DownloadError, DownloadOptions, Downloader, SlabFetcher, UploadError, UploadOptions, Uploader,
};

use crate::app_client::{Account, Client, ObjectsCursor, RegisterAppRequest};
use log::debug;
use sia::encryption::EncryptionKey;
use sia::rhp::Host;
use sia::signing::PrivateKey;
use sia::types::Hash256;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use reqwest::{IntoUrl, Url};
pub use slabs::*;

pub struct DisconnectedState;

pub struct RegisteredState {
    app: Client,
    app_key: PrivateKey,

    connect_url: Option<Url>,
    status_url: Option<Url>,
}

pub struct ConnectedState {
    app: Client,
    downloader: Downloader,
    uploader: Uploader,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("app error: {0}")]
    App(String),

    #[error("upload error: {0}")]
    Upload(#[from] UploadError),

    #[error("download error: {0}")]
    Download(#[from] DownloadError),

    #[error("TLS error: {0}")]
    Tls(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct SDK<S> {
    state: S,
}

impl SDK<DisconnectedState> {
    pub async fn connect(
        app_url: &str,
        app_key: PrivateKey,
        app_name: String,
        app_description: String,
        app_service_url: Url,
    ) -> Result<SDK<RegisteredState>> {
        let client =
            Client::new(app_url, app_key.clone()).map_err(|e| Error::App(format!("{e:?}")))?;

        let authenticated = client
            .check_app_authenticated()
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        if authenticated {
            debug!("app connected and authenticated");
            return Ok(SDK {
                state: RegisteredState {
                    app: client,
                    app_key,
                    connect_url: None,
                    status_url: None,
                },
            });
        }

        debug!("requesting app connection");
        let res = client
            .request_app_connection(&RegisterAppRequest {
                name: app_name,
                description: app_description,
                service_url: app_service_url,
                logo_url: None,
                callback_url: None,
            })
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        debug!("app connected, awaiting approval");
        Ok(SDK {
            state: RegisteredState {
                app: client,
                app_key,
                connect_url: Some(
                    res.response_url
                        .parse()
                        .map_err(|e| Error::App(format!("{e:?}")))?,
                ),
                status_url: Some(
                    res.status_url
                        .parse()
                        .map_err(|e| Error::App(format!("{e:?}")))?,
                ),
            },
        })
    }
}

impl SDK<RegisteredState> {
    pub fn needs_approval(&self) -> bool {
        self.state.connect_url.is_some()
    }

    pub fn approval_url(&self) -> Option<&Url> {
        self.state.connect_url.as_ref()
    }

    pub async fn connected(self, tls_config: rustls::ClientConfig) -> Result<SDK<ConnectedState>> {
        if self.state.connect_url.is_some() {
            loop {
                let ok = self
                    .state
                    .app
                    .check_request_status(self.state.status_url.clone().unwrap())
                    .await
                    .map_err(|e| Error::App(format!("{e:?}")))?;
                if ok {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            tokio::time::sleep(Duration::from_secs(30)).await; // wait for accounts to get funded
        }

        let hosts = self
            .state
            .app
            .hosts()
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        let dialer = quic::Client::new(tls_config).map_err(|e| Error::Tls(format!("{e:?}")))?;
        dialer.update_hosts(hosts);

        let downloader = Downloader::new(
            self.state.app.clone(),
            dialer.clone(),
            self.state.app_key.clone(),
        );
        let uploader = Uploader::new(
            self.state.app.clone(),
            dialer.clone(),
            self.state.app_key.clone(),
        );

        Ok(SDK {
            state: ConnectedState {
                app: self.state.app,
                downloader,
                uploader,
            },
        })
    }
}

impl SDK<ConnectedState> {
    pub async fn upload<R: AsyncReadExt + Unpin + Send + 'static>(
        &self,
        reader: R,
        metadata: Option<Vec<u8>>,
        options: UploadOptions,
    ) -> Result<UploadMeta> {
        let upload_meta = self
            .state
            .uploader
            .upload(reader, metadata, options)
            .await?;
        Ok(upload_meta)
    }

    pub async fn download<W: AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
        encryption_key: EncryptionKey,
        object: &Object,
        options: DownloadOptions,
    ) -> Result<()> {
        let slab_iterator = SlabFetcher::new(self.state.app.clone(), object.slabs.clone());
        self.state
            .downloader
            .download(writer, encryption_key, slab_iterator, options)
            .await?;
        Ok(())
    }

    pub async fn hosts(&self) -> Result<Vec<Host>> {
        self.state
            .app
            .hosts()
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    pub async fn slab(&self, slab_id: &Hash256) -> Result<PinnedSlab> {
        self.state
            .app
            .slab(slab_id)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    pub async fn account(&self) -> Result<Account> {
        self.state
            .app
            .account()
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    pub async fn slab_ids(&self, offset: Option<u64>, limit: Option<u64>) -> Result<Vec<Hash256>> {
        self.state
            .app
            .slab_ids(offset, limit)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    pub async fn object(&self, key: &Hash256) -> Result<Object> {
        self.state
            .app
            .object(key)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
            .and_then(|obj| {
                obj.validate_object()
                    .map(|_| obj)
                    .map_err(|err| Error::App(err.to_string()))
            })
    }

    pub async fn objects(
        &self,
        cursor: Option<ObjectsCursor>,
        limit: Option<usize>,
    ) -> Result<Vec<Object>> {
        self.state
            .app
            .objects(cursor, limit)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
            .and_then(|objs| {
                objs.into_iter()
                    .map(|obj| {
                        obj.validate_object()
                            .map(|_| obj)
                            .map_err(|err| Error::App(err.to_string()))
                    })
                    .collect()
            })
    }

    pub async fn save_object(&self, object: &Object) -> Result<()> {
        self.state
            .app
            .save_object(object)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        Ok(())
    }

    pub async fn delete_object(&self, key: &Hash256) -> Result<()> {
        self.state
            .app
            .delete_object(key)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }
}
