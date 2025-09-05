mod app_client;

use crate::app_client::{Client, RegisterAppRequest};
pub use reqwest::{IntoUrl, Url};
use rustls_platform_verifier::ConfigVerifierExt;
use sia::objects::slabs::Slab;
use sia::objects::{Downloader, HostDialer, Uploader};
use sia::rhp::quic::Dialer;
use sia::signing::PrivateKey;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct DisconnectedState;

pub struct RegisteredState {
    app: Client,
    app_key: PrivateKey,

    connect_url: Option<Url>,
    status_url: Option<Url>,
}

pub struct ConnectedState {
    downloader: Downloader<Dialer>,
    uploader: Uploader<Dialer>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("app error: {0}")]
    App(String),
    #[error("SDK error: {0}")]
    SDK(String),
    #[error("TLS error: {0}")]
    Tls(String),
}

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
    ) -> Result<SDK<RegisteredState>, Error> {
        let client =
            Client::new(app_url, app_key.clone()).map_err(|e| Error::App(format!("{e:?}")))?;

        let authenticated = client
            .check_app_authenticated()
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        if authenticated {
            return Ok(SDK {
                state: RegisteredState {
                    app: client,
                    app_key,
                    connect_url: None,
                    status_url: None,
                },
            });
        }

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

    pub async fn connected(
        self,
        tls_config: Option<rustls::ClientConfig>,
    ) -> Result<SDK<ConnectedState>, Error> {
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

        if rustls::crypto::CryptoProvider::get_default().is_none() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .map_err(|e| Error::Tls(format!("{e:?}")))?;
        }
        let tls_config = match tls_config {
            Some(c) => c,
            None => rustls::ClientConfig::with_platform_verifier()
                .map_err(|_| Error::Tls("with_platform_verifier() failed".into()))?,
        };

        let hosts = self
            .state
            .app
            .hosts()
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;

        let mut dialer = Dialer::new(tls_config).map_err(|e| Error::Tls(format!("{e:?}")))?;
        dialer.update_hosts(hosts);

        let downloader = Downloader::new(dialer.clone(), self.state.app_key.clone(), 12);
        let uploader = Uploader::new(dialer.clone(), self.state.app_key.clone(), 12);

        Ok(SDK {
            state: ConnectedState {
                downloader,
                uploader,
            },
        })
    }
}

impl SDK<ConnectedState> {
    pub async fn upload<R: AsyncReadExt + Unpin + Send + 'static>(
        &self,
        reader: &mut R,
        encryption_key: [u8; 32],
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Vec<Slab>, Error> {
        self.state
            .uploader
            .upload(reader, encryption_key, data_shards, parity_shards)
            .await
            .map_err(|e| Error::SDK(format!("{e:?}")))
    }

    pub async fn download<W: AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
        slabs: &[Slab],
    ) -> Result<(), Error> {
        self.state
            .downloader
            .download(writer, slabs)
            .await
            .map_err(|e| Error::SDK(format!("{e:?}")))
    }
}
