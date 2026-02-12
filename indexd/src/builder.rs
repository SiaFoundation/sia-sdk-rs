use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use log::debug;
use reqwest::IntoUrl;
use sia::seed::{self, Seed};
use sia::signing::PrivateKey;
use sia::types::Hash256;
use thiserror::Error;
use url::Url;

use crate::app_client::{self, AppClient, Client, RegisterAppRequest};
use crate::object_encryption::derive;
use crate::{SDK, quic};

/// The initial state of the SDK builder, before connecting to the indexd service.
pub struct DisconnectedState;

/// The state of the SDK builder after requesting approval for the application.
pub struct RequestingApprovalState {
    app_id: Hash256,
    response_url: Url,
    register_url: Url,
    status_url: Url,
    expiration: DateTime<Utc>,
}

/// The state of the SDK builder after the application has been approved.
pub struct ApprovedState {
    app_id: Hash256,
    register_url: Url,
    user_secret: Hash256,
}

/// A builder for creating an SDK instance.
pub struct Builder<S> {
    state: S,
    client: Client,
}

/// Errors that can occur during the SDK building process.
#[derive(Error, Debug)]
pub enum BuilderError {
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    #[error("client error: {0}")]
    Client(#[from] app_client::Error),

    #[error("quic error: {0}")]
    QUIC(#[from] quic::ConnectError),

    #[error("mnemonic error: {0}")]
    Mnemonic(#[from] seed::SeedError),

    #[error("request expired")]
    RequestExpired,
}

impl Builder<DisconnectedState> {
    /// Creates a new SDK builder with the provided indexer URL.
    ///
    /// After creating the builder, call [Builder::connected] to attempt
    /// to connect using an existing app key, or [Builder::request_connection]
    /// to request a new connection.
    pub fn new<U: IntoUrl>(indexer_url: U) -> Result<Self, BuilderError> {
        debug!(
            "Creating SDK builder for indexer at {}",
            indexer_url.as_str()
        );
        let client = Client::new(indexer_url)?;
        Ok(Self {
            state: DisconnectedState,
            client,
        })
    }

    /// Attempts to connect using the provided app key and TLS configuration.
    /// If the app key is valid, returns Some([SDK]), otherwise returns None.
    ///
    /// If you receive None, call [Builder::request_connection] to request a new connection.
    ///
    /// # Arguments
    /// * `app_key` - The application key used for authentication.
    /// * `tls_config` - The TLS configuration for secure communication.
    pub async fn connected(
        &self,
        app_key: &PrivateKey,
        tls_config: rustls::ClientConfig,
    ) -> Result<Option<SDK>, BuilderError> {
        let connected = self.client.check_app_authenticated(app_key).await?;
        if !connected {
            return Ok(None);
        }
        let sdk = SDK::new(self.client.clone(), Arc::new(app_key.clone()), tls_config).await?;
        Ok(Some(sdk))
    }

    /// Requests a new connection for the application.
    ///
    /// # Arguments
    /// * `app` - Details of the application requesting connection.
    pub async fn request_connection(
        self,
        app: &RegisterAppRequest,
    ) -> Result<Builder<RequestingApprovalState>, BuilderError> {
        let resp = self.client.request_app_connection(app).await?;
        Ok(Builder {
            state: RequestingApprovalState {
                app_id: app.app_id,
                response_url: Url::parse(&resp.response_url)?,
                register_url: Url::parse(&resp.register_url)?,
                status_url: Url::parse(&resp.status_url)?,
                expiration: resp.expiration,
            },
            client: self.client,
        })
    }
}

impl Builder<RequestingApprovalState> {
    /// Returns the response URL for the registration process. This
    /// should be displayed to the user so they can authorize the
    /// application.
    pub fn response_url(&self) -> &str {
        self.state.response_url.as_str()
    }

    /// Waits for the application registration to be approved. This
    /// polls the status URL until the registration is approved or
    /// rejected. This can take several minutes depending on user action.
    ///
    /// [Builder::response_url] should be displayed to the user
    /// before calling this method.
    pub async fn wait_for_approval(self) -> Result<Builder<ApprovedState>, BuilderError> {
        loop {
            if Utc::now() >= self.state.expiration {
                return Err(BuilderError::RequestExpired);
            }

            if let Some(user_secret) = self
                .client
                .check_request_status(self.state.status_url.clone())
                .await?
            {
                return Ok(Builder {
                    state: ApprovedState {
                        app_id: self.state.app_id,
                        register_url: self.state.register_url.clone(),
                        user_secret,
                    },
                    client: self.client,
                });
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

impl Builder<ApprovedState> {
    /// Completes the registration process and returns an SDK instance.
    ///
    /// # Arguments
    /// * `mnemonic` - The user's mnemonic phrase used to derive the application key.
    /// * `tls_config` - The TLS configuration for secure communication.
    ///
    /// # Errors
    /// Returns [BuilderError] if the registration fails or the SDK cannot be created.
    pub async fn register(
        self,
        mnemonic: &str,
        tls_config: rustls::ClientConfig,
    ) -> Result<SDK, BuilderError> {
        let app_key = derive_app_key(mnemonic, &self.state.app_id, &self.state.user_secret)?;
        self.client
            .register_app(&app_key, self.state.register_url.clone())
            .await?;
        SDK::new(self.client, Arc::new(app_key), tls_config).await
    }
}

/// A helper function to derive an application key from a
/// mnemonic, app ID, and shared secret.
///
/// It is exposed to be able to test the app key derivation logic.
fn derive_app_key(
    mnemonic: &str,
    app_id: &Hash256,
    shared_secret: &Hash256,
) -> Result<PrivateKey, BuilderError> {
    const KEY_DOMAIN: &[u8] = b"indexd app key derivation";
    let seed = Seed::new(mnemonic)?;
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(seed.entropy());
    key[32..].copy_from_slice(shared_secret.as_ref());
    let mut okm = [0u8; 32];
    derive(&key, app_id.as_ref(), KEY_DOMAIN, &mut okm);
    Ok(PrivateKey::from_seed(&okm))
}

#[cfg(test)]
mod test {
    use super::*;
    use sia::hash_256;
    use sia::types::Hash256;

    #[test]
    fn test_app_key_derivation_golden() {
        const MNEMONIC: &str =
            "glare own entire dish exact open theme family harsh room scrap rose";
        const APP_ID: Hash256 =
            hash_256!("0e90d697f5045a6593f1c43ebf79a369e2bc72cc5c7b6282f3b5aeb0de6e4005");
        const SHARED_SECRET: Hash256 =
            hash_256!("cf02d945fe4bfe614d823dc13c19aa8501699e656d0f7915490c3056d5c97dc6");
        const EXPECTED_APP_KEY: &str =
            "b75061f34bb3aeab232b0671da2d0347c547343a0026bb5535c291d964fd09a1";

        let mut seed = [0u8; 32];
        hex::decode_to_slice(EXPECTED_APP_KEY, &mut seed).expect("decoding failed");
        let expected_app_key = PrivateKey::from_seed(&seed);

        let derived_app_key =
            derive_app_key(MNEMONIC, &APP_ID, &SHARED_SECRET).expect("derivation failed");
        assert_eq!(derived_app_key, expected_app_key);
    }
}
